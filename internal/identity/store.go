package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrInviteInvalid    = errors.New("invite invalid")
	ErrInviteRedeemed   = errors.New("invite redeemed")
	ErrClaimRateLimited = errors.New("claim rate limited")
	ErrUsernameTaken    = errors.New("username already claimed")
	ErrNotFound         = errors.New("not found")
	ErrUnauthorized     = errors.New("unauthorized")
)

var usernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

type AccountStatus string

const (
	StatusActive      AccountStatus = "active"
	StatusSuspended   AccountStatus = "suspended"
	StatusSoftDeleted AccountStatus = "soft_deleted"
)

type InviteLevel int

const (
	InviteRoot InviteLevel = 0
	InviteA    InviteLevel = 1
	InviteB    InviteLevel = 2
	InviteC    InviteLevel = 3
)

func (l InviteLevel) childCount() int {
	switch l {
	case InviteRoot:
		return 3
	case InviteA:
		return 2
	case InviteB:
		return 1
	default:
		return 0
	}
}

type ClaimLimits struct {
	PerSourcePerHour int
	PerSourcePerDay  int
	GlobalPerHour    int
	GlobalPerDay     int
	RetentionDays    int
}

type Account struct {
	Username  string        `json:"username"`
	PubKey    string        `json:"pubkey"`
	Status    AccountStatus `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	DeletedAt *time.Time    `json:"deleted_at,omitempty"`
}

type SpoolMessage struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	Alias      string    `json:"alias"`
	Sender     string    `json:"sender"`
	Ciphertext string    `json:"ciphertext"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type InviteRequestStatus string

const (
	InviteRequestPending      InviteRequestStatus = "pending"
	InviteRequestAcknowledged InviteRequestStatus = "acknowledged"
)

type InviteRequest struct {
	ID           int64               `json:"id"`
	Email        string              `json:"email"`
	Note         string              `json:"note,omitempty"`
	SourceBucket string              `json:"source_bucket"`
	Status       InviteRequestStatus `json:"status"`
	CreatedAt    time.Time           `json:"created_at"`
	UpdatedAt    time.Time           `json:"updated_at"`
}

type Store struct {
	db                 *sql.DB
	pepper             string
	maxCiphertextBytes int
	apiKeyRetention    time.Duration
}

func Open(path, pepper string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{
		db:                 db,
		pepper:             strings.TrimSpace(pepper),
		maxCiphertextBytes: 256 * 1024,
		apiKeyRetention:    30 * 24 * time.Hour,
	}
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=ON;`,
	}
	for _, p := range pragmas {
		if _, err := s.db.Exec(p); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);`); err != nil {
		return err
	}
	v, err := s.currentSchemaVersion()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= v {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return err
		}
	}
	return nil
}

type migration struct {
	version int
	stmts   []string
}

var migrations = []migration{
	{
		version: 1,
		stmts: []string{
			`CREATE TABLE IF NOT EXISTS accounts (
			username TEXT PRIMARY KEY,
			pubkey TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			deleted_at TEXT
		);`,
			`CREATE TABLE IF NOT EXISTS invites (
			code_hash TEXT PRIMARY KEY,
			parent_hash TEXT,
			level INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			redeemed_by TEXT,
			redeemed_at TEXT
		);`,
			`CREATE TABLE IF NOT EXISTS claim_log (
			ts_unix INTEGER NOT NULL,
			source_bucket TEXT NOT NULL
		);`,
			`CREATE INDEX IF NOT EXISTS idx_claim_log_ts ON claim_log(ts_unix);`,
			`CREATE INDEX IF NOT EXISTS idx_claim_log_bucket_ts ON claim_log(source_bucket, ts_unix);`,
			`CREATE TABLE IF NOT EXISTS spool_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			alias TEXT NOT NULL,
			sender TEXT NOT NULL,
			ciphertext TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
			`CREATE INDEX IF NOT EXISTS idx_spool_user_exp ON spool_messages(username, expires_at);`,
			`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			revoked_at TEXT,
			last_used_at TEXT
		);`,
			`CREATE INDEX IF NOT EXISTS idx_api_keys_user_rev ON api_keys(username, revoked_at);`,
			`CREATE TABLE IF NOT EXISTS invite_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			note TEXT NOT NULL,
			source_bucket TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
			`CREATE INDEX IF NOT EXISTS idx_invite_requests_status_created ON invite_requests(status, created_at);`,
		},
	},
}

func (s *Store) currentSchemaVersion() (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

func (s *Store) applyMigration(m migration) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, st := range m.stmts {
		if _, err := tx.Exec(st); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, m.version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetMaxCiphertextBytes(n int) {
	if n > 0 {
		s.maxCiphertextBytes = n
	}
}

func (s *Store) SetAPIKeyRetention(d time.Duration) {
	if d > 0 {
		s.apiKeyRetention = d
	}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) PurgeRevokedAPIKeys(ctx context.Context, now time.Time) error {
	if s.apiKeyRetention <= 0 {
		return nil
	}
	cut := now.UTC().Add(-s.apiKeyRetention).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE revoked_at IS NOT NULL AND revoked_at != '' AND revoked_at <= ?`, cut)
	return err
}

func (s *Store) EnqueueCiphertext(ctx context.Context, username, alias, sender, ciphertext string, ttl time.Duration) (*SpoolMessage, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, err
	}
	alias = strings.TrimSpace(alias)
	sender = strings.TrimSpace(sender)
	ciphertext = strings.TrimSpace(ciphertext)
	if alias == "" || sender == "" || ciphertext == "" {
		return nil, fmt.Errorf("missing alias/sender/ciphertext")
	}
	if s.maxCiphertextBytes > 0 && len(ciphertext) > s.maxCiphertextBytes {
		return nil, fmt.Errorf("ciphertext too large")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	acc, err := s.GetAccount(ctx, u)
	if err != nil {
		return nil, err
	}
	if acc.Status != StatusActive {
		return nil, fmt.Errorf("account not active")
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	res, err := s.db.ExecContext(ctx, `INSERT INTO spool_messages(username, alias, sender, ciphertext, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?)`,
		u, alias, sender, ciphertext, now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &SpoolMessage{
		ID:         id,
		Username:   u,
		Alias:      alias,
		Sender:     sender,
		Ciphertext: ciphertext,
		CreatedAt:  now,
		ExpiresAt:  expires,
	}, nil
}

func (s *Store) ListCiphertext(ctx context.Context, username string, now time.Time, limit int) ([]SpoolMessage, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, alias, sender, ciphertext, created_at, expires_at
		FROM spool_messages WHERE username=? AND expires_at>? ORDER BY id ASC LIMIT ?`, u, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SpoolMessage, 0, limit)
	for rows.Next() {
		var (
			m                SpoolMessage
			created, expires string
		)
		if err := rows.Scan(&m.ID, &m.Username, &m.Alias, &m.Sender, &m.Ciphertext, &created, &expires); err != nil {
			return nil, err
		}
		m.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		m.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMessage(ctx context.Context, username string, id int64) error {
	u, err := CanonicalUsername(username)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM spool_messages WHERE username=? AND id=?`, u, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM spool_messages WHERE expires_at<=?`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func CanonicalUsername(in string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(in))
	if !usernameRE.MatchString(u) {
		return "", fmt.Errorf("invalid username")
	}
	return u, nil
}

func (s *Store) MintRootInvites(ctx context.Context, n int) ([]string, error) {
	if n <= 0 || n > 10000 {
		return nil, fmt.Errorf("invalid invite count")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	out := make([]string, 0, n)
	for len(out) < n {
		code, err := randomCode()
		if err != nil {
			return nil, err
		}
		h := s.inviteHash(code)
		_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash, parent_hash, level, created_at) VALUES(?, NULL, ?, ?)`, h, int(InviteRoot), now)
		if err != nil {
			if isConstraint(err) {
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

func (s *Store) ClaimWithInvite(ctx context.Context, username, pubkey, inviteCode, sourceBucket string, limits ClaimLimits) (*Account, []string, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(pubkey) == "" {
		return nil, nil, fmt.Errorf("missing pubkey")
	}
	code := strings.TrimSpace(inviteCode)
	if code == "" {
		return nil, nil, ErrInviteInvalid
	}
	sourceBucket = strings.TrimSpace(sourceBucket)
	if sourceBucket == "" {
		sourceBucket = "unknown"
	}

	now := time.Now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	nowUnix := now.Unix()
	h := s.inviteHash(code)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// no squatting via open claim; invite required and rate-limited.
	if err := enforceClaimLimits(ctx, tx, sourceBucket, nowUnix, limits); err != nil {
		return nil, nil, err
	}

	// username uniqueness.
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE username=?`, u).Scan(&existing); err != nil {
		return nil, nil, err
	}
	if existing > 0 {
		return nil, nil, ErrUsernameTaken
	}

	var (
		level      int
		redeemedBy sql.NullString
	)
	if err := tx.QueryRowContext(ctx, `SELECT level, redeemed_by FROM invites WHERE code_hash=?`, h).Scan(&level, &redeemedBy); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, ErrInviteInvalid
		}
		return nil, nil, err
	}
	if redeemedBy.Valid && strings.TrimSpace(redeemedBy.String) != "" {
		return nil, nil, ErrInviteRedeemed
	}

	res, err := tx.ExecContext(ctx, `UPDATE invites SET redeemed_by=?, redeemed_at=? WHERE code_hash=? AND (redeemed_by IS NULL OR redeemed_by='')`, u, nowText, h)
	if err != nil {
		return nil, nil, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return nil, nil, ErrInviteRedeemed
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts(username, pubkey, status, created_at, updated_at, deleted_at) VALUES(?, ?, ?, ?, ?, NULL)`, u, strings.TrimSpace(pubkey), string(StatusActive), nowText, nowText); err != nil {
		if isConstraint(err) {
			return nil, nil, ErrUsernameTaken
		}
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO claim_log(ts_unix, source_bucket) VALUES(?, ?)`, nowUnix, sourceBucket); err != nil {
		return nil, nil, err
	}
	if err := pruneClaimLog(ctx, tx, nowUnix, limits.RetentionDays); err != nil {
		return nil, nil, err
	}

	lvl := InviteLevel(level)
	childN := lvl.childCount()
	children := make([]string, 0, childN)
	for len(children) < childN {
		c, err := randomCode()
		if err != nil {
			return nil, nil, err
		}
		ch := s.inviteHash(c)
		_, err = tx.ExecContext(ctx, `INSERT INTO invites(code_hash, parent_hash, level, created_at) VALUES(?, ?, ?, ?)`, ch, h, level+1, nowText)
		if err != nil {
			if isConstraint(err) {
				continue
			}
			return nil, nil, err
		}
		children = append(children, c)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	acc := &Account{Username: u, PubKey: strings.TrimSpace(pubkey), Status: StatusActive, CreatedAt: now, UpdatedAt: now}
	return acc, children, nil
}

func (s *Store) SoftDelete(ctx context.Context, username string) error {
	u, err := CanonicalUsername(username)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET status=?, updated_at=?, deleted_at=? WHERE username=?`, string(StatusSoftDeleted), now, now, u)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Restore(ctx context.Context, username string) error {
	u, err := CanonicalUsername(username)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET status=?, updated_at=?, deleted_at=NULL WHERE username=?`, string(StatusActive), now, u)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetAccount(ctx context.Context, username string) (*Account, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return nil, err
	}
	var (
		a                    Account
		createdAt, updatedAt string
		deletedAt            sql.NullString
	)
	err = s.db.QueryRowContext(ctx, `SELECT username, pubkey, status, created_at, updated_at, deleted_at FROM accounts WHERE username=?`, u).
		Scan(&a.Username, &a.PubKey, &a.Status, &createdAt, &updatedAt, &deletedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	a.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	if deletedAt.Valid && strings.TrimSpace(deletedAt.String) != "" {
		t, _ := time.Parse(time.RFC3339Nano, deletedAt.String)
		a.DeletedAt = &t
	}
	return &a, nil
}

func (s *Store) CreateInviteRequest(ctx context.Context, email, note, sourceBucket string) (*InviteRequest, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	note = strings.TrimSpace(note)
	sourceBucket = strings.TrimSpace(sourceBucket)
	if email == "" || !strings.Contains(email, "@") || len(email) > 254 {
		return nil, fmt.Errorf("invalid email")
	}
	if sourceBucket == "" {
		sourceBucket = "unknown"
	}
	if len(note) > 1000 {
		note = note[:1000]
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT INTO invite_requests(email, note, source_bucket, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)`,
		email, note, sourceBucket, string(InviteRequestPending), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &InviteRequest{
		ID:           id,
		Email:        email,
		Note:         note,
		SourceBucket: sourceBucket,
		Status:       InviteRequestPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (s *Store) ListInviteRequests(ctx context.Context, status string, limit int) ([]InviteRequest, error) {
	status = strings.TrimSpace(strings.ToLower(status))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if status == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, email, note, source_bucket, status, created_at, updated_at FROM invite_requests ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, email, note, source_bucket, status, created_at, updated_at FROM invite_requests WHERE status=? ORDER BY id DESC LIMIT ?`, status, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]InviteRequest, 0, limit)
	for rows.Next() {
		var (
			r               InviteRequest
			created, update string
		)
		if err := rows.Scan(&r.ID, &r.Email, &r.Note, &r.SourceBucket, &r.Status, &created, &update); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		r.UpdatedAt, _ = time.Parse(time.RFC3339Nano, update)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeInviteRequest(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("invalid id")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `UPDATE invite_requests SET status=?, updated_at=? WHERE id=?`,
		string(InviteRequestAcknowledged), now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) IssueAPIKey(ctx context.Context, username string) (string, error) {
	u, err := CanonicalUsername(username)
	if err != nil {
		return "", err
	}
	acc, err := s.GetAccount(ctx, u)
	if err != nil {
		return "", err
	}
	if acc.Status != StatusActive {
		return "", fmt.Errorf("account not active")
	}
	key, err := randomAPIKey()
	if err != nil {
		return "", err
	}
	h := s.keyHash(key)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE api_keys SET revoked_at=? WHERE username=? AND (revoked_at IS NULL OR revoked_at='')`, now, u); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys(username, key_hash, created_at, revoked_at, last_used_at) VALUES(?, ?, ?, NULL, NULL)`, u, h, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return key, nil
}

func (s *Store) AuthenticateAPIKey(ctx context.Context, presented string) (string, error) {
	key := strings.TrimSpace(presented)
	if key == "" {
		return "", ErrUnauthorized
	}
	h := s.keyHash(key)
	var username string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM api_keys WHERE key_hash=? AND (revoked_at IS NULL OR revoked_at='')`, h).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrUnauthorized
		}
		return "", err
	}
	acc, err := s.GetAccount(ctx, username)
	if err != nil {
		if err == ErrNotFound {
			return "", ErrUnauthorized
		}
		return "", err
	}
	if acc.Status != StatusActive {
		return "", ErrUnauthorized
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at=? WHERE key_hash=?`, now, h)
	return username, nil
}

func (s *Store) RotateAPIKey(ctx context.Context, presented string) (string, string, error) {
	key := strings.TrimSpace(presented)
	if key == "" {
		return "", "", ErrUnauthorized
	}
	oldHash := s.keyHash(key)
	newKey, err := randomAPIKey()
	if err != nil {
		return "", "", err
	}
	newHash := s.keyHash(newKey)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()

	var username string
	if err := tx.QueryRowContext(ctx, `SELECT username FROM api_keys WHERE key_hash=? AND (revoked_at IS NULL OR revoked_at='')`, oldHash).Scan(&username); err != nil {
		if err == sql.ErrNoRows {
			return "", "", ErrUnauthorized
		}
		return "", "", err
	}
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM accounts WHERE username=?`, username).Scan(&status); err != nil {
		if err == sql.ErrNoRows {
			return "", "", ErrUnauthorized
		}
		return "", "", err
	}
	if AccountStatus(status) != StatusActive {
		return "", "", ErrUnauthorized
	}
	res, err := tx.ExecContext(ctx, `UPDATE api_keys SET revoked_at=? WHERE key_hash=? AND (revoked_at IS NULL OR revoked_at='')`, now, oldHash)
	if err != nil {
		return "", "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", "", ErrUnauthorized
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys(username, key_hash, created_at, revoked_at, last_used_at) VALUES(?, ?, ?, NULL, NULL)`, username, newHash, now); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return username, newKey, nil
}

func (s *Store) inviteHash(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s.pepper) + ":" + strings.TrimSpace(code)))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (s *Store) keyHash(key string) string {
	sum := sha256.Sum256([]byte("api:" + strings.TrimSpace(s.pepper) + ":" + strings.TrimSpace(key)))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func enforceClaimLimits(ctx context.Context, tx *sql.Tx, source string, nowUnix int64, l ClaimLimits) error {
	if l.PerSourcePerHour > 0 {
		if n, err := countClaims(ctx, tx, source, nowUnix-3600); err != nil {
			return err
		} else if n >= l.PerSourcePerHour {
			return ErrClaimRateLimited
		}
	}
	if l.PerSourcePerDay > 0 {
		if n, err := countClaims(ctx, tx, source, nowUnix-86400); err != nil {
			return err
		} else if n >= l.PerSourcePerDay {
			return ErrClaimRateLimited
		}
	}
	if l.GlobalPerHour > 0 {
		if n, err := countClaimsGlobal(ctx, tx, nowUnix-3600); err != nil {
			return err
		} else if n >= l.GlobalPerHour {
			return ErrClaimRateLimited
		}
	}
	if l.GlobalPerDay > 0 {
		if n, err := countClaimsGlobal(ctx, tx, nowUnix-86400); err != nil {
			return err
		} else if n >= l.GlobalPerDay {
			return ErrClaimRateLimited
		}
	}
	return nil
}

func countClaims(ctx context.Context, tx *sql.Tx, source string, since int64) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_log WHERE source_bucket=? AND ts_unix>=?`, source, since).Scan(&n)
	return n, err
}

func countClaimsGlobal(ctx context.Context, tx *sql.Tx, since int64) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_log WHERE ts_unix>=?`, since).Scan(&n)
	return n, err
}

func pruneClaimLog(ctx context.Context, tx *sql.Tx, nowUnix int64, days int) error {
	if days <= 0 {
		return nil
	}
	cut := nowUnix - int64(days*86400)
	_, err := tx.ExecContext(ctx, `DELETE FROM claim_log WHERE ts_unix<?`, cut)
	return err
}

func randomCode() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(b[:])
	enc = strings.ToUpper(enc)
	if len(enc) > 20 {
		enc = enc[:20]
	}
	return enc, nil
}

func randomAPIKey() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "smk_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "constraint")
}
