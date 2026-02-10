package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(dbPath string) (*Store, error) {
	// modernc.org/sqlite is pure Go and works without CGO.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// Keep this conservative; the relay should not hold long SQLite locks.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS identities (
  username    TEXT PRIMARY KEY,
  pubkey      TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  ipv6_addr   TEXT NOT NULL UNIQUE,
  created_at  TEXT NOT NULL,
  last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS alloc_state (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  next_host  INTEGER NOT NULL
);
`)
	return err
}

type Identity struct {
	Username    string
	PubKey      ssh.PublicKey
	PubKeyText  string
	Fingerprint string
	IPv6        net.IP
	CreatedAt   time.Time
	LastSeen    *time.Time
}

func FingerprintSHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Store) Put(ctx context.Context, username string, pubKeyText string, ipv6 net.IP) error {
	if username == "" {
		return fmt.Errorf("missing username")
	}
	if ipv6 == nil || ipv6.To16() == nil || ipv6.To4() != nil {
		return fmt.Errorf("ipv6 must be a valid IPv6 address")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyText))
	if err != nil {
		return fmt.Errorf("parse pubkey: %w", err)
	}
	fp := FingerprintSHA256(pub)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = s.db.ExecContext(ctx, `
INSERT INTO identities (username, pubkey, fingerprint, ipv6_addr, created_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(username) DO UPDATE SET
  pubkey=excluded.pubkey,
  fingerprint=excluded.fingerprint,
  ipv6_addr=excluded.ipv6_addr
`, username, pubKeyText, fp, ipv6.String(), now)
	return err
}

// Claim creates a new identity if unclaimed, allocating an IPv6 from the given /64.
// If the username already exists, it verifies the key matches and returns the existing record.
//
// This is the relay's v1 "no recovery" model: first key to claim binds the name.
func (s *Store) Claim(ctx context.Context, username string, pubKey ssh.PublicKey, ipv6Prefix *net.IPNet) (*Identity, bool, error) {
	if username == "" {
		return nil, false, fmt.Errorf("missing username")
	}
	if pubKey == nil {
		return nil, false, fmt.Errorf("missing pubkey")
	}
	if ipv6Prefix == nil || ipv6Prefix.IP == nil || ipv6Prefix.IP.To16() == nil {
		return nil, false, fmt.Errorf("invalid ipv6 prefix")
	}
	ones, bits := ipv6Prefix.Mask.Size()
	if bits != 128 || ones != 64 {
		return nil, false, fmt.Errorf("ipv6 prefix must be /64")
	}

	// First check if it already exists.
	existing, err := s.GetByUsername(ctx, username)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if subtleComparePub(existing.PubKey, pubKey) {
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("username claimed by different key")
	}

	// Allocate inside a transaction so concurrent claims don't collide.
	var allocated net.IP
	pubKeyText := string(ssh.MarshalAuthorizedKey(pubKey))
	fp := FingerprintSHA256(pubKey)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	nextHost, err := allocNextHost(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	allocated, err = ipv6FromHost(ipv6Prefix, nextHost)
	if err != nil {
		return nil, false, err
	}
	if err := bumpNextHost(ctx, tx, nextHost+1); err != nil {
		return nil, false, err
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO identities (username, pubkey, fingerprint, ipv6_addr, created_at)
VALUES (?, ?, ?, ?, ?)
`, username, pubKeyText, fp, allocated.String(), now)
	if err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	ct, _ := time.Parse(time.RFC3339Nano, now)
	return &Identity{
		Username:    username,
		PubKey:      pubKey,
		PubKeyText:  pubKeyText,
		Fingerprint: fp,
		IPv6:        allocated,
		CreatedAt:   ct,
		LastSeen:    nil,
	}, true, nil
}

func allocNextHost(ctx context.Context, tx *sql.Tx) (uint64, error) {
	// Seed at a non-trivial offset so early addresses aren't ::1, ::2, etc.
	const seed = uint64(0x1000)
	row := tx.QueryRowContext(ctx, `SELECT next_host FROM alloc_state WHERE id = 1`)
	var n sql.NullInt64
	if err := row.Scan(&n); err != nil {
		if err == sql.ErrNoRows {
			if _, err := tx.ExecContext(ctx, `INSERT INTO alloc_state (id, next_host) VALUES (1, ?)`, int64(seed)); err != nil {
				return 0, err
			}
			return seed, nil
		}
		return 0, err
	}
	if !n.Valid || n.Int64 <= 0 {
		return seed, nil
	}
	return uint64(n.Int64), nil
}

func bumpNextHost(ctx context.Context, tx *sql.Tx, next uint64) error {
	_, err := tx.ExecContext(ctx, `UPDATE alloc_state SET next_host = ? WHERE id = 1`, int64(next))
	return err
}

func ipv6FromHost(prefix *net.IPNet, host uint64) (net.IP, error) {
	base := prefix.IP.To16()
	if base == nil {
		return nil, fmt.Errorf("invalid base ip")
	}
	ip := make(net.IP, 16)
	copy(ip, base)
	// For a /64, the host ID occupies the low 64 bits.
	binary.BigEndian.PutUint64(ip[8:], host)
	return ip, nil
}

func subtleComparePub(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	am := a.Marshal()
	bm := b.Marshal()
	if len(am) != len(bm) {
		return false
	}
	var v byte
	for i := 0; i < len(am); i++ {
		v |= am[i] ^ bm[i]
	}
	return v == 0
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*Identity, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT username, pubkey, fingerprint, ipv6_addr, created_at, last_seen
FROM identities WHERE username = ?
`, username)
	var (
		u, pkText, fp, ipStr, created, last sql.NullString
	)
	if err := row.Scan(&u, &pkText, &fp, &ipStr, &created, &last); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pkText.String))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr.String)
	if ip == nil {
		return nil, fmt.Errorf("invalid ipv6 in db")
	}
	ct, err := time.Parse(time.RFC3339Nano, created.String)
	if err != nil {
		return nil, err
	}
	var lt *time.Time
	if last.Valid && last.String != "" {
		tm, err := time.Parse(time.RFC3339Nano, last.String)
		if err == nil {
			lt = &tm
		}
	}
	return &Identity{
		Username:    u.String,
		PubKey:      pub,
		PubKeyText:  pkText.String,
		Fingerprint: fp.String,
		IPv6:        ip,
		CreatedAt:   ct,
		LastSeen:    lt,
	}, nil
}

func (s *Store) DeleteByUsername(ctx context.Context, username string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE username = ?`, username)
	return err
}

func (s *Store) All(ctx context.Context) ([]Identity, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT username, pubkey, fingerprint, ipv6_addr, created_at, last_seen
FROM identities
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Identity
	for rows.Next() {
		var (
			u, pkText, fp, ipStr, created, last sql.NullString
		)
		if err := rows.Scan(&u, &pkText, &fp, &ipStr, &created, &last); err != nil {
			return nil, err
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pkText.String))
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(ipStr.String)
		if ip == nil {
			return nil, fmt.Errorf("invalid ipv6 in db")
		}
		ct, err := time.Parse(time.RFC3339Nano, created.String)
		if err != nil {
			return nil, err
		}
		var lt *time.Time
		if last.Valid && last.String != "" {
			tm, err := time.Parse(time.RFC3339Nano, last.String)
			if err == nil {
				lt = &tm
			}
		}
		out = append(out, Identity{
			Username:    u.String,
			PubKey:      pub,
			PubKeyText:  pkText.String,
			Fingerprint: fp.String,
			IPv6:        ip,
			CreatedAt:   ct,
			LastSeen:    lt,
		})
	}
	return out, rows.Err()
}

func (s *Store) TouchLastSeen(ctx context.Context, username string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.ExecContext(ctx, `UPDATE identities SET last_seen=? WHERE username=?`, now, username)
}
