package tier2

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// StreamEncrypt reads plaintext from src, encrypts it to the given SSH public
// key (authorized_keys format), and writes ciphertext to dst.
//
// This is the core of Tier 2's §12 streaming requirement: the caller can
// connect src to an SMTP DATA reader and dst to a spool file writer, so
// plaintext is never fully buffered in memory.
func StreamEncrypt(dst io.Writer, src io.Reader, sshPubKey string) error {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubKey))
	if err != nil {
		return fmt.Errorf("parse ssh pubkey: %w", err)
	}

	recipient, err := agessh.NewEd25519Recipient(pubKey)
	if err != nil {
		return fmt.Errorf("create age recipient: %w", err)
	}

	w, err := age.Encrypt(dst, recipient)
	if err != nil {
		return fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("encrypt stream: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("finalize encryption: %w", err)
	}

	return nil
}

// StreamDecrypt reads ciphertext from src, decrypts it using the given SSH
// private key (PEM format), and writes plaintext to dst.
func StreamDecrypt(dst io.Writer, src io.Reader, sshPrivKeyPEM string) error {
	rawKey, err := ssh.ParseRawPrivateKey([]byte(sshPrivKeyPEM))
	if err != nil {
		return fmt.Errorf("parse ssh private key: %w", err)
	}

	ed25519Key, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("expected *ed25519 private key, got %T", rawKey)
	}

	identity, err := agessh.NewEd25519Identity(*ed25519Key)
	if err != nil {
		return fmt.Errorf("create age identity: %w", err)
	}

	r, err := age.Decrypt(src, identity)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("decrypt stream: %w", err)
	}

	return nil
}
