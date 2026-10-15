package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

const encryptedModeratorKeyPrefix = "enc:v1:"

// moderatorKeyCipher keeps moderator credentials encrypted in SQLite. The
// encryption key is domain-separated from the independently stored admin API
// token, so copying only the database never exposes moderator credentials.
type moderatorKeyCipher struct {
	aead cipher.AEAD
}

func newModeratorKeyCipher(keyMaterial []byte) (*moderatorKeyCipher, error) {
	if len(keyMaterial) != 32 {
		return nil, fmt.Errorf("moderator key encryption key must be 32 bytes")
	}
	key := sha256.Sum256(append([]byte("symposium/moderator-key-at-rest/v1\x00"), keyMaterial...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &moderatorKeyCipher{aead: aead}, nil
}

func loadOrCreateModeratorKeyEncryptionKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("moderator key encryption key path is required")
	}
	readExisting := func() ([]byte, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("moderator key encryption key must be a regular file")
		}
		if info.Mode().Perm()&0o007 != 0 {
			return nil, fmt.Errorf("moderator key encryption key is accessible to other users")
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			for i := range key {
				key[i] = 0
			}
			return nil, fmt.Errorf("moderator key encryption key must contain exactly 32 bytes")
		}
		return key, nil
	}

	key, err := readExisting()
	if err == nil {
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		for i := range key {
			key[i] = 0
		}
		if os.IsExist(err) {
			return readExisting()
		}
		return nil, err
	}
	_, writeErr := file.Write(key)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return key, nil
}

func moderatorKeyAAD(roomName string) []byte {
	return []byte("symposium/room/v1\x00" + strings.TrimSpace(roomName))
}

func (c *moderatorKeyCipher) seal(roomName string, plaintext string) (string, error) {
	if c == nil || c.aead == nil {
		return "", fmt.Errorf("moderator key cipher is not configured")
	}
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", fmt.Errorf("moderator key is empty")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), moderatorKeyAAD(roomName))
	return encryptedModeratorKeyPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *moderatorKeyCipher) open(roomName string, stored string) (string, error) {
	if c == nil || c.aead == nil {
		return "", fmt.Errorf("moderator key cipher is not configured")
	}
	stored = strings.TrimSpace(stored)
	if !strings.HasPrefix(stored, encryptedModeratorKeyPrefix) {
		return "", fmt.Errorf("moderator key is not encrypted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, encryptedModeratorKeyPrefix))
	if err != nil {
		return "", fmt.Errorf("decode moderator key: %w", err)
	}
	if len(raw) < c.aead.NonceSize() {
		return "", fmt.Errorf("encrypted moderator key is truncated")
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, moderatorKeyAAD(roomName))
	if err != nil {
		return "", fmt.Errorf("decrypt moderator key: %w", err)
	}
	value := strings.TrimSpace(string(plaintext))
	for i := range plaintext {
		plaintext[i] = 0
	}
	if value == "" {
		return "", fmt.Errorf("decrypted moderator key is empty")
	}
	return value, nil
}
