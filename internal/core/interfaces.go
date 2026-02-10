// Package core defines the shared interface contracts that all Sisumail
// modules target. No implementations live here — only types and interfaces.
//
// Adding to this file is the one allowed cross-module edit.
// Each workstream implements one or more of these interfaces in its own package.
package core

import (
	"io"
	"net"
	"time"
)

// ---------------------------------------------------------------------------
// Identity (§4.3 — Minimal Registry State)
// ---------------------------------------------------------------------------

// UserRecord is the minimal identity state the relay stores.
type UserRecord struct {
	Username    string
	SSHPubKey   string // authorized_keys format (ssh-ed25519 AAAA...)
	Fingerprint string // SHA256:...
	DestIPv6    net.IP // unique per-user Tier 1 destination
	CreatedAt   time.Time
}

// IdentityStore provides read-only access to user records.
// Used by WS1 (DNS provisioner), WS2 (key resolver), and WS5 (key directory).
type IdentityStore interface {
	LookupByUsername(username string) (*UserRecord, error)
	LookupByDomain(domain string) (*UserRecord, error) // "<user>.sisumail.fi" → record
	ListAll() ([]UserRecord, error)
}

// ---------------------------------------------------------------------------
// DNS (§7 — Split MX Architecture)
// ---------------------------------------------------------------------------

// DNSRecord represents a single DNS record to be created or deleted.
type DNSRecord struct {
	Type  string // MX, AAAA, TXT, CAA
	Name  string // FQDN, e.g. "niklas.sisumail.fi"
	Value string // record value
	TTL   int    // seconds, 0 = provider default
}

// DNSProvider manages DNS records via a hosting API.
type DNSProvider interface {
	CreateRecord(zoneID string, rec DNSRecord) (recordID string, err error)
	DeleteRecord(zoneID, recordID string) error
	ListRecords(zoneID, name string) ([]DNSRecordEntry, error)
	GetZoneIDByName(zoneName string) (string, error)
}

// DNSRecordEntry is a record returned from the provider, including its ID.
type DNSRecordEntry struct {
	ID    string
	Type  string
	Name  string
	Value string
	TTL   int
}

// DNSProvisioner is the high-level interface for user DNS lifecycle.
type DNSProvisioner interface {
	ProvisionUser(username string, destIPv6 net.IP) error
	DeprovisionUser(username string) error
}

// ---------------------------------------------------------------------------
// Tier 2 Spool (§12 — Encrypt-on-Ingest)
// ---------------------------------------------------------------------------

// KeyResolver looks up the recipient's SSH public key for Tier 2 encryption.
// Input is the recipient domain (e.g. "niklas.sisumail.fi").
type KeyResolver interface {
	Resolve(domain string) (sshPubKey string, err error)
}

// SpoolMeta is the metadata stored alongside ciphertext in the spool.
type SpoolMeta struct {
	MessageID  string    `json:"message_id"`
	Recipient  string    `json:"recipient"`   // "<user>.sisumail.fi"
	ReceivedAt time.Time `json:"received_at"`
	SizeBytes  int64     `json:"size_bytes"`  // ciphertext size
	Tier       string    `json:"tier"`        // always "tier2"
}

// SpoolStore writes and reads encrypted Tier 2 spool entries.
type SpoolStore interface {
	Put(user, msgID string, ciphertext io.Reader, meta SpoolMeta) error
	Get(user, msgID string) (ciphertext io.ReadCloser, meta SpoolMeta, err error)
	Ack(user, msgID string) error // mark delivered + delete
	List(user string) ([]SpoolMeta, error)
}

// ---------------------------------------------------------------------------
// Maildir (§5.2 — Edge Storage, Client-Side Only)
// ---------------------------------------------------------------------------

// MaildirEntry describes a message stored in Maildir.
type MaildirEntry struct {
	ID        string
	Filename  string
	Size      int64
	Tier      string // "tier1" or "tier2"
	Timestamp time.Time
}

// MaildirStore manages local message storage on the user's device.
type MaildirStore interface {
	Deliver(msg io.Reader, tier string) (id string, err error)
	List() ([]MaildirEntry, error)
	Read(id string) (io.ReadCloser, error)
}

// ---------------------------------------------------------------------------
// Alias Intelligence (§5.2 — Client-Side Only)
// ---------------------------------------------------------------------------

// AliasStats tracks per-tag usage statistics.
type AliasStats struct {
	Tag              string
	UseCount         int
	FirstSeen        time.Time
	LastSeen         time.Time
	UniqueSenders    int
	SenderDomains    []string
	ProbableLeak     bool
}

// AliasTracker manages alias tag tracking and leak detection.
// All state lives on the user's device; the relay never sees this data.
type AliasTracker interface {
	Parse(rcptTo string) (localPart, tag string)
	RecordUse(tag, senderDomain string, at time.Time)
	Stats(tag string) (AliasStats, error)
	DetectLeak(tag string) bool
	ListTags() ([]string, error)
}

// ---------------------------------------------------------------------------
// Key Directory (§13 — Lookup-Only)
// ---------------------------------------------------------------------------

// KeyDirectory is the lookup-only public-key directory for chat.
type KeyDirectory interface {
	Lookup(username string) (sshPubKey string, err error)
}
