package identity

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "id.db"), "pepper")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func TestInviteFanout3210(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}

	roots, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint root: %v", err)
	}
	a1, c1, err := s.ClaimWithInvite(ctx, "alice", "pk1", roots[0], "src1", limits)
	if err != nil {
		t.Fatalf("claim alice: %v", err)
	}
	if a1.Status != StatusActive || len(c1) != 3 {
		t.Fatalf("expected active + 3 invites, got status=%s invites=%d", a1.Status, len(c1))
	}

	_, c2, err := s.ClaimWithInvite(ctx, "bob", "pk2", c1[0], "src2", limits)
	if err != nil {
		t.Fatalf("claim bob: %v", err)
	}
	if len(c2) != 2 {
		t.Fatalf("expected 2 invites, got %d", len(c2))
	}

	_, c3, err := s.ClaimWithInvite(ctx, "carl", "pk3", c2[0], "src3", limits)
	if err != nil {
		t.Fatalf("claim carl: %v", err)
	}
	if len(c3) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(c3))
	}

	_, c4, err := s.ClaimWithInvite(ctx, "dina", "pk4", c3[0], "src4", limits)
	if err != nil {
		t.Fatalf("claim dina: %v", err)
	}
	if len(c4) != 0 {
		t.Fatalf("expected 0 invites, got %d", len(c4))
	}
}

func TestInviteSingleUseAndRateLimit(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	limits := ClaimLimits{PerSourcePerHour: 1, PerSourcePerDay: 10, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}

	codes, err := s.MintRootInvites(ctx, 2)
	if err != nil {
		t.Fatalf("mint root: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk1", codes[0], "1.2.3.4", limits); err != nil {
		t.Fatalf("claim alice: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "bob", "pk2", codes[0], "9.9.9.9", limits); err != ErrInviteRedeemed {
		t.Fatalf("expected redeemed error, got %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "carl", "pk3", codes[1], "1.2.3.4", limits); err != ErrClaimRateLimited {
		t.Fatalf("expected rate limit, got %v", err)
	}
}

func TestSoftDeleteRestore(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}
	codes, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk", codes[0], "src", limits); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.SoftDelete(ctx, "alice"); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	acc, err := s.GetAccount(ctx, "alice")
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if acc.Status != StatusSoftDeleted || acc.DeletedAt == nil {
		t.Fatalf("expected soft deleted + deleted_at, got status=%s deleted_at=%v", acc.Status, acc.DeletedAt)
	}
	if err := s.Restore(ctx, "alice"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	acc, err = s.GetAccount(ctx, "alice")
	if err != nil {
		t.Fatalf("get account after restore: %v", err)
	}
	if acc.Status != StatusActive || acc.DeletedAt != nil {
		t.Fatalf("expected active + nil deleted_at, got status=%s deleted_at=%v", acc.Status, acc.DeletedAt)
	}
}

func TestSpoolTTLAndManualDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}
	codes, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk", codes[0], "src", limits); err != nil {
		t.Fatalf("claim: %v", err)
	}

	msg, err := s.EnqueueCiphertext(ctx, "alice", "steam@alice.sisumail.fi", "support@steampowered.com", "ciphertext-1", 15*time.Minute)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	list, err := s.ListCiphertext(ctx, "alice", time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != msg.ID {
		t.Fatalf("expected one message, got %+v", list)
	}

	// Manual delete within TTL.
	if err := s.DeleteMessage(ctx, "alice", msg.ID); err != nil {
		t.Fatalf("delete message: %v", err)
	}
	list, err = s.ListCiphertext(ctx, "alice", time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(list))
	}

	// Enqueue new message with short TTL and purge.
	_, err = s.EnqueueCiphertext(ctx, "alice", "steam@alice.sisumail.fi", "support@steampowered.com", "ciphertext-2", 1*time.Second)
	if err != nil {
		t.Fatalf("enqueue short ttl: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	n, err := s.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one purged message")
	}
}

func TestAPIKeyIssueAuthRotate(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}
	codes, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk", codes[0], "src", limits); err != nil {
		t.Fatalf("claim: %v", err)
	}

	key, err := s.IssueAPIKey(ctx, "alice")
	if err != nil {
		t.Fatalf("issue api key: %v", err)
	}
	if key == "" {
		t.Fatal("expected non-empty api key")
	}
	username, err := s.AuthenticateAPIKey(ctx, key)
	if err != nil {
		t.Fatalf("auth api key: %v", err)
	}
	if username != "alice" {
		t.Fatalf("expected alice, got %q", username)
	}

	rotUser, newKey, err := s.RotateAPIKey(ctx, key)
	if err != nil {
		t.Fatalf("rotate api key: %v", err)
	}
	if rotUser != "alice" || newKey == "" || newKey == key {
		t.Fatalf("bad rotate response user=%q key=%q", rotUser, newKey)
	}
	if _, err := s.AuthenticateAPIKey(ctx, key); err != ErrUnauthorized {
		t.Fatalf("expected old key unauthorized, got %v", err)
	}
	if username, err := s.AuthenticateAPIKey(ctx, newKey); err != nil || username != "alice" {
		t.Fatalf("expected new key valid for alice, got user=%q err=%v", username, err)
	}
}

func TestInviteRequestCreateListAcknowledge(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()

	req, err := s.CreateInviteRequest(ctx, "Niklas@example.com", "I want access", "10.0.0.1")
	if err != nil {
		t.Fatalf("create invite request: %v", err)
	}
	if req.Status != InviteRequestPending {
		t.Fatalf("expected pending, got %s", req.Status)
	}

	list, err := s.ListInviteRequests(ctx, "pending", 10)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(list) == 0 || list[0].ID != req.ID {
		t.Fatalf("expected request id %d in list, got %+v", req.ID, list)
	}

	if err := s.AcknowledgeInviteRequest(ctx, req.ID); err != nil {
		t.Fatalf("ack request: %v", err)
	}
	ackList, err := s.ListInviteRequests(ctx, "acknowledged", 10)
	if err != nil {
		t.Fatalf("list acknowledged: %v", err)
	}
	if len(ackList) == 0 || ackList[0].ID != req.ID {
		t.Fatalf("expected acknowledged request id %d in list, got %+v", req.ID, ackList)
	}
}

func TestCiphertextSizeLimit(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	s.SetMaxCiphertextBytes(8)

	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}
	codes, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk", codes[0], "src", limits); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := s.EnqueueCiphertext(ctx, "alice", "steam@alice.sisumail.fi", "support@steampowered.com", "ciphertext-too-large", 1*time.Minute); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestPurgeRevokedAPIKeys(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	defer s.Close()
	s.SetAPIKeyRetention(1 * time.Second)

	limits := ClaimLimits{PerSourcePerHour: 100, PerSourcePerDay: 100, GlobalPerHour: 1000, GlobalPerDay: 1000, RetentionDays: 30}
	codes, err := s.MintRootInvites(ctx, 1)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, _, err := s.ClaimWithInvite(ctx, "alice", "pk", codes[0], "src", limits); err != nil {
		t.Fatalf("claim: %v", err)
	}
	k1, err := s.IssueAPIKey(ctx, "alice")
	if err != nil {
		t.Fatalf("issue k1: %v", err)
	}
	if _, _, err := s.RotateAPIKey(ctx, k1); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if err := s.PurgeRevokedAPIKeys(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("purge revoked keys: %v", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NOT NULL AND revoked_at != ''`).Scan(&n); err != nil {
		t.Fatalf("count revoked: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected revoked keys to be purged, got %d", n)
	}
}
