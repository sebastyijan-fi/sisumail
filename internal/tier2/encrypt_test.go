package tier2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func genTestKeyPair(t *testing.T) (pubKeyText string, privKeyPEM string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh signer: %v", err)
	}
	pubKeyText = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	privKeyPEM = string(pem.EncodeToMemory(block))
	return pubKeyText, privKeyPEM
}

func TestStreamEncryptDecryptRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"small", "Hello, world!"},
		{"1KB", strings.Repeat("A", 1024)},
		{"multiline RFC5322", "From: sender@example.com\r\nTo: user@sisumail.fi\r\nSubject: Test\r\n\r\nThis is the body.\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSSHPubKey, testSSHPrivKey := genTestKeyPair(t)

			// Encrypt.
			var ciphertext bytes.Buffer
			if err := StreamEncrypt(&ciphertext, strings.NewReader(tt.input), testSSHPubKey); err != nil {
				t.Fatalf("StreamEncrypt: %v", err)
			}

			// Ciphertext should not contain plaintext.
			if tt.input != "" && bytes.Contains(ciphertext.Bytes(), []byte(tt.input)) {
				t.Fatal("ciphertext contains plaintext")
			}

			// Decrypt.
			var plaintext bytes.Buffer
			if err := StreamDecrypt(&plaintext, &ciphertext, testSSHPrivKey); err != nil {
				t.Fatalf("StreamDecrypt: %v", err)
			}

			if plaintext.String() != tt.input {
				t.Fatalf("round-trip mismatch:\n  got:  %q\n  want: %q", plaintext.String(), tt.input)
			}
		})
	}
}

func TestStreamEncryptInvalidKey(t *testing.T) {
	var buf bytes.Buffer
	err := StreamEncrypt(&buf, strings.NewReader("test"), "not-a-valid-key")
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestStreamDecryptWrongKey(t *testing.T) {
	// Encrypt with one key, try to decrypt with a different identity.
	testSSHPubKey, _ := genTestKeyPair(t)
	var ciphertext bytes.Buffer
	if err := StreamEncrypt(&ciphertext, strings.NewReader("secret message"), testSSHPubKey); err != nil {
		t.Fatalf("StreamEncrypt: %v", err)
	}

	// Use a different key for decryption.
	_, wrongKey := genTestKeyPair(t)

	var plaintext bytes.Buffer
	err := StreamDecrypt(&plaintext, &ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}
