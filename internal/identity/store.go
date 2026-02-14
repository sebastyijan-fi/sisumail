package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

var ErrClaimRateLimited = errors.New("claim rate limited")

type ClaimLimits struct {
	// PerSourcePerHour limits the number of *new* identity claims per bucket per hour.
	// (IPv4 buckets are typically /24, IPv6 buckets typically /64.)
	PerSourcePerHour int
	PerSourcePerDay  int
	GlobalPerHour    int
	GlobalPerDay     int

	// RetentionDays controls how long we keep claim_log rows (0 disables pruning).
	// This only needs to cover the longest window (day); keep it > 1 in practice.
	RetentionDays int
}

func Open(dbPath string) (*Store, error) {
	// modernc.org/sqlite is pure Go and works without CGO.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// Improve concurrency characteristics:
	// - WAL allows concurrent readers while a writer is active.
	// - busy_timeout makes concurrent writes wait briefly instead of failing fast.
	// If these pragmas fail, continue; the DB will still work, just more lock-prone.
	_, _ = db.Exec(`PRAGMA journal_mode = WAL;`)
	_, _ = db.Exec(`PRAGMA busy_timeout = 5000;`) // milliseconds
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

CREATE TABLE IF NOT EXISTS claim_log (
  ts_unix       INTEGER NOT NULL,
  source_bucket TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claim_log_ts ON claim_log(ts_unix);
CREATE INDEX IF NOT EXISTS idx_claim_log_bucket_ts ON claim_log(source_bucket, ts_unix);

CREATE TABLE IF NOT EXISTS invites (
  code_hash    TEXT PRIMARY KEY,
  parent_hash  TEXT,
  level        INTEGER NOT NULL,
  created_at   TEXT NOT NULL,
  redeemed_by  TEXT,
  redeemed_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_invites_parent ON invites(parent_hash);
CREATE INDEX IF NOT EXISTS idx_invites_redeemed_by ON invites(redeemed_by);
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
	u, err := CanonicalUsername(username)
	if err != nil {
		return err
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
`, u, pubKeyText, fp, ipv6.String(), now)
	return err
}

// Claim creates a new identity if unclaimed, allocating an IPv6 from the given /64.
// If the username already exists, it verifies the key matches and returns the existing record.
//
// This is the relay's v1 "no recovery" model: first key to claim binds the name.
//
// For open first-claim deployments, operators SHOULD enable claim limits to reduce squatting.
func (s *Store) Claim(ctx context.Context, username string, pubKey ssh.PublicKey, ipv6Prefix *net.IPNet, sourceBucket string, limits ClaimLimits) (*Identity, bool, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, false, err
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

	sourceBucket = strings.TrimSpace(sourceBucket)
	if sourceBucket == "" {
		sourceBucket = "unknown"
	}

	// Allocate + enforce limits inside a transaction so concurrent claims don't collide.
	var allocated net.IP
	pubKeyText := string(ssh.MarshalAuthorizedKey(pubKey))
	fp := FingerprintSHA256(pubKey)
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	nowUnix := now.Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// First check if it already exists.
	existing, err := getByUsernameTx(ctx, tx, u)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		if subtleComparePub(existing.PubKey, pubKey) {
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("username claimed by different key")
	}

	if err := enforceClaimLimits(ctx, tx, sourceBucket, nowUnix, limits); err != nil {
		return nil, false, err
	}

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
`, u, pubKeyText, fp, allocated.String(), nowText)
	if err != nil {
		return nil, false, err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO claim_log (ts_unix, source_bucket) VALUES (?, ?)`, nowUnix, sourceBucket)
	if err != nil {
		return nil, false, err
	}
	if err := pruneClaimLog(ctx, tx, nowUnix, limits.RetentionDays); err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	return &Identity{
		Username:    u,
		PubKey:      pubKey,
		PubKeyText:  pubKeyText,
		Fingerprint: fp,
		IPv6:        allocated,
		CreatedAt:   now,
		LastSeen:    nil,
	}, true, nil
}

func getByUsernameTx(ctx context.Context, tx *sql.Tx, username string) (*Identity, error) {
	row := tx.QueryRowContext(ctx, `
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

func enforceClaimLimits(ctx context.Context, tx *sql.Tx, sourceBucket string, nowUnix int64, lim ClaimLimits) error {
	// 0/negative limits disable that dimension.
	hourStart := nowUnix - 3600
	dayStart := nowUnix - 86400

	if lim.PerSourcePerHour > 0 {
		c, err := countClaimsSince(ctx, tx, sourceBucket, hourStart)
		if err != nil {
			return err
		}
		if c >= lim.PerSourcePerHour {
			return ErrClaimRateLimited
		}
	}
	if lim.PerSourcePerDay > 0 {
		c, err := countClaimsSince(ctx, tx, sourceBucket, dayStart)
		if err != nil {
			return err
		}
		if c >= lim.PerSourcePerDay {
			return ErrClaimRateLimited
		}
	}
	if lim.GlobalPerHour > 0 {
		c, err := countClaimsGlobalSince(ctx, tx, hourStart)
		if err != nil {
			return err
		}
		if c >= lim.GlobalPerHour {
			return ErrClaimRateLimited
		}
	}
	if lim.GlobalPerDay > 0 {
		c, err := countClaimsGlobalSince(ctx, tx, dayStart)
		if err != nil {
			return err
		}
		if c >= lim.GlobalPerDay {
			return ErrClaimRateLimited
		}
	}
	return nil
}

func countClaimsSince(ctx context.Context, tx *sql.Tx, sourceBucket string, sinceUnix int64) (int, error) {
	row := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_log WHERE source_bucket = ? AND ts_unix >= ?`, sourceBucket, sinceUnix)
	var c int
	if err := row.Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func countClaimsGlobalSince(ctx context.Context, tx *sql.Tx, sinceUnix int64) (int, error) {
	row := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_log WHERE ts_unix >= ?`, sinceUnix)
	var c int
	if err := row.Scan(&c); err != nil {
		return 0, err
	}
	return c, nil
}

func pruneClaimLog(ctx context.Context, tx *sql.Tx, nowUnix int64, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}
	if retentionDays > 365 {
		// Prevent misconfig causing huge deletion queries to run forever.
		retentionDays = 365
	}
	cutoff := nowUnix - int64(retentionDays)*86400
	_, err := tx.ExecContext(ctx, `DELETE FROM claim_log WHERE ts_unix < ?`, cutoff)
	return err
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
	canon, err := CanonicalUsername(username)
	if err != nil {
		return nil, nil
	}
	row := s.db.QueryRowContext(ctx, `
SELECT username, pubkey, fingerprint, ipv6_addr, created_at, last_seen
FROM identities WHERE username = ?
`, canon)
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
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM identities WHERE username = ?`, u)
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
	u, err := CanonicalUsername(username)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.ExecContext(ctx, `UPDATE identities SET last_seen=? WHERE username=?`, now, u)
}

// ---- Invite-only claim (v1) -------------------------------------------------

type InviteLevel int

const (
	InviteLevelRoot InviteLevel = 0
	InviteLevelA    InviteLevel = 1
	InviteLevelB    InviteLevel = 2
	InviteLevelC    InviteLevel = 3
)

func (l InviteLevel) childCount() int {
	switch l {
	case InviteLevelRoot:
		return 3
	case InviteLevelA:
		return 2
	case InviteLevelB:
		return 1
	default:
		return 0
	}
}

type Invite struct {
	CodeHash   string
	ParentHash *string
	Level      InviteLevel
	CreatedAt  time.Time
	RedeemedBy *string
	RedeemedAt *time.Time
}

var (
	ErrInviteInvalid  = errors.New("invite invalid")
	ErrInviteRedeemed = errors.New("invite already redeemed")
)

// MintRootInvites creates N new root-level invite codes and returns plaintext codes.
// The plaintext codes are not stored; only their hash is persisted.
func (s *Store) MintRootInvites(ctx context.Context, n int, pepper string) ([]string, error) {
	if n <= 0 || n > 10000 {
		return nil, fmt.Errorf("invalid invite count")
	}
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	out := make([]string, 0, n)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	for len(out) < n {
		code, err := randomInviteCode()
		if err != nil {
			return nil, err
		}
		h := inviteHash(code, pepper)
		_, err = tx.ExecContext(ctx, `
INSERT INTO invites (code_hash, parent_hash, level, created_at)
VALUES (?, NULL, ?, ?)
`, h, int(InviteLevelRoot), nowText)
		if err != nil {
			// Collision is astronomically unlikely; if it happens, retry.
			if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
				continue
			}
			return nil, err
		}
		out = append(out, code)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// RedeemInvite atomically marks an invite as redeemed_by. It returns newly created child invite codes.
// Child codes are returned in plaintext once; only hashes are stored.
func (s *Store) RedeemInvite(ctx context.Context, inviteCode string, redeemByUsername string, pepper string) ([]string, error) {
	code := strings.TrimSpace(inviteCode)
	if code == "" {
		return nil, ErrInviteInvalid
	}
	redeemBy, err := CanonicalUsername(redeemByUsername)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	h := inviteHash(code, pepper)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
SELECT level, redeemed_by, parent_hash
FROM invites
WHERE code_hash = ?
`, h)
	var (
		levelInt               int
		redeemedByDB, parentDB sql.NullString
	)
	if err := row.Scan(&levelInt, &redeemedByDB, &parentDB); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInviteInvalid
		}
		return nil, err
	}
	if redeemedByDB.Valid && strings.TrimSpace(redeemedByDB.String) != "" {
		return nil, ErrInviteRedeemed
	}
	lvl := InviteLevel(levelInt)
	if lvl < InviteLevelRoot || lvl > InviteLevelC {
		return nil, ErrInviteInvalid
	}

	_, err = tx.ExecContext(ctx, `
UPDATE invites
SET redeemed_by = ?, redeemed_at = ?
WHERE code_hash = ? AND (redeemed_by IS NULL OR redeemed_by = '')
`, redeemBy, nowText, h)
	if err != nil {
		return nil, err
	}

	childN := lvl.childCount()
	children := make([]string, 0, childN)
	for len(children) < childN {
		cc, err := randomInviteCode()
		if err != nil {
			return nil, err
		}
		ch := inviteHash(cc, pepper)
		_, err = tx.ExecContext(ctx, `
INSERT INTO invites (code_hash, parent_hash, level, created_at)
VALUES (?, ?, ?, ?)
`, ch, h, int(lvl+1), nowText)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
				continue
			}
			return nil, err
		}
		children = append(children, cc)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return children, nil
}

// ClaimWithInvite is the production onboarding path: invite-only first-claim with IPv6 allocation.
// It atomically (1) validates + redeems the invite, (2) enforces claim limits, (3) allocates IPv6,
// (4) writes the identity, and (5) mints child invites for the new user.
func (s *Store) ClaimWithInvite(ctx context.Context, username string, pubKey ssh.PublicKey, ipv6Prefix *net.IPNet, sourceBucket string, limits ClaimLimits, inviteCode string, pepper string) (*Identity, []string, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, nil, err
	}
	if pubKey == nil {
		return nil, nil, fmt.Errorf("missing pubkey")
	}
	if ipv6Prefix == nil || ipv6Prefix.IP == nil || ipv6Prefix.IP.To16() == nil {
		return nil, nil, fmt.Errorf("invalid ipv6 prefix")
	}
	ones, bits := ipv6Prefix.Mask.Size()
	if bits != 128 || ones != 64 {
		return nil, nil, fmt.Errorf("ipv6 prefix must be /64")
	}
	code := strings.TrimSpace(inviteCode)
	if code == "" {
		return nil, nil, ErrInviteInvalid
	}
	sourceBucket = strings.TrimSpace(sourceBucket)
	if sourceBucket == "" {
		sourceBucket = "unknown"
	}

	pubKeyText := string(ssh.MarshalAuthorizedKey(pubKey))
	fp := FingerprintSHA256(pubKey)
	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	nowUnix := now.Unix()
	invHash := inviteHash(code, pepper)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Username must be unclaimed.
	existing, err := getByUsernameTx(ctx, tx, u)
	if err != nil {
		return nil, nil, err
	}
	if existing != nil {
		return nil, nil, fmt.Errorf("username already claimed")
	}
	// Enforce rate limits for new claims (invite-only still benefits from throttling).
	if err := enforceClaimLimits(ctx, tx, sourceBucket, nowUnix, limits); err != nil {
		return nil, nil, err
	}

	// Validate invite and lock it by updating redeemed_by conditionally.
	row := tx.QueryRowContext(ctx, `
SELECT level, redeemed_by
FROM invites
WHERE code_hash = ?
`, invHash)
	var levelInt int
	var redeemedByDB sql.NullString
	if err := row.Scan(&levelInt, &redeemedByDB); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, ErrInviteInvalid
		}
		return nil, nil, err
	}
	if redeemedByDB.Valid && strings.TrimSpace(redeemedByDB.String) != "" {
		return nil, nil, ErrInviteRedeemed
	}
	lvl := InviteLevel(levelInt)
	if lvl < InviteLevelRoot || lvl > InviteLevelC {
		return nil, nil, ErrInviteInvalid
	}
	_, err = tx.ExecContext(ctx, `
UPDATE invites
SET redeemed_by = ?, redeemed_at = ?
WHERE code_hash = ? AND (redeemed_by IS NULL OR redeemed_by = '')
`, u, nowText, invHash)
	if err != nil {
		return nil, nil, err
	}

	// Allocate IPv6 and insert identity.
	nextHost, err := allocNextHost(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	allocated, err := ipv6FromHost(ipv6Prefix, nextHost)
	if err != nil {
		return nil, nil, err
	}
	if err := bumpNextHost(ctx, tx, nextHost+1); err != nil {
		return nil, nil, err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO identities (username, pubkey, fingerprint, ipv6_addr, created_at)
VALUES (?, ?, ?, ?, ?)
`, u, pubKeyText, fp, allocated.String(), nowText)
	if err != nil {
		return nil, nil, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO claim_log (ts_unix, source_bucket) VALUES (?, ?)`, nowUnix, sourceBucket)
	if err != nil {
		return nil, nil, err
	}
	if err := pruneClaimLog(ctx, tx, nowUnix, limits.RetentionDays); err != nil {
		return nil, nil, err
	}

	// Mint child invites for the new account.
	childN := lvl.childCount()
	children := make([]string, 0, childN)
	for len(children) < childN {
		cc, err := randomInviteCode()
		if err != nil {
			return nil, nil, err
		}
		ch := inviteHash(cc, pepper)
		_, err = tx.ExecContext(ctx, `
INSERT INTO invites (code_hash, parent_hash, level, created_at)
VALUES (?, ?, ?, ?)
`, ch, invHash, int(lvl+1), nowText)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
				continue
			}
			return nil, nil, err
		}
		children = append(children, cc)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &Identity{
		Username:    u,
		PubKey:      pubKey,
		PubKeyText:  pubKeyText,
		Fingerprint: fp,
		IPv6:        allocated,
		CreatedAt:   now,
		LastSeen:    nil,
	}, children, nil
}

func randomInviteCode() (string, error) {
	// 20 chars base32 without padding from 12 random bytes.
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(b[:])
	enc = strings.TrimRight(enc, "=")
	enc = strings.NewReplacer("+", "A", "/", "B").Replace(enc)
	enc = strings.ToUpper(enc)
	// Make it shorter/printable.
	if len(enc) > 20 {
		enc = enc[:20]
	}
	return enc, nil
}

func inviteHash(code string, pepper string) string {
	// Pepper is optional (dev). For production, set SISUMAIL_INVITE_PEPPER.
	msg := strings.TrimSpace(code)
	pep := strings.TrimSpace(pepper)
	sum := sha256.Sum256([]byte(pep + ":" + msg))
	return base64.StdEncoding.EncodeToString(sum[:])
}
