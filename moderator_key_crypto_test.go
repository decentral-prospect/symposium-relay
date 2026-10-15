package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModeratorKeyCipherRoundTripAndRoomBinding(t *testing.T) {
	cipher, err := newModeratorKeyCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	const plaintext = "moderator-secret-value"
	sealed, err := cipher.seal("room-a", plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed == plaintext || strings.Contains(sealed, plaintext) || !strings.HasPrefix(sealed, encryptedModeratorKeyPrefix) {
		t.Fatalf("invalid encrypted representation: %q", sealed)
	}
	opened, err := cipher.open("room-a", sealed)
	if err != nil || opened != plaintext {
		t.Fatalf("open = %q, %v", opened, err)
	}
	if _, err := cipher.open("room-b", sealed); err == nil {
		t.Fatal("encrypted moderator key was not bound to its room")
	}
}

func TestModeratorKeyEncryptionKeyFileIsStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "moderator-key.bin")
	first, err := loadOrCreateModeratorKeyEncryptionKey(path)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	second, err := loadOrCreateModeratorKeyEncryptionKey(path)
	if err != nil {
		t.Fatalf("reload key: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("reloaded moderator key encryption key changed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key permissions = %o, want 600", got)
	}
}
