package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

const (
	testFrameE2EESecretBytes = 32
	testFrameE2EEIVBytes     = 12
	testFrameE2EETagBytes    = 16
	frameE2EEKeyIndex        = byte(0)
)

var testFrameE2EERatchetSalt = []byte("SymposiumFrameEncryptionKey/v1")

// testFrameCryptor implements the wire format used by the Android WebRTC
// FrameCryptor. It exists only in tests so the host peer can authenticate and
// decrypt Android's encoded frames while the relay remains unaware of the key.
type testFrameCryptor struct {
	aead    cipher.AEAD
	counter atomic.Uint64
}

func newTestFrameCryptor(encodedSecret string) (*testFrameCryptor, error) {
	material, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(material) != testFrameE2EESecretBytes {
		return nil, errors.New("invalid conference E2EE secret")
	}
	derived := pbkdf2.Key(material, testFrameE2EERatchetSalt, 100_000, 16, sha256.New)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	if aead.NonceSize() != testFrameE2EEIVBytes || aead.Overhead() != testFrameE2EETagBytes {
		return nil, errors.New("unexpected AES-GCM parameters")
	}
	return &testFrameCryptor{aead: aead}, nil
}

func (c *testFrameCryptor) encryptFrame(plain []byte, clearHeaderBytes int) ([]byte, error) {
	if c == nil || clearHeaderBytes < 0 || len(plain) < clearHeaderBytes {
		return nil, errors.New("invalid frame encryption input")
	}
	iv := make([]byte, testFrameE2EEIVBytes)
	if _, err := rand.Read(iv[:4]); err != nil {
		return nil, fmt.Errorf("generate frame IV: %w", err)
	}
	binary.BigEndian.PutUint64(iv[4:], c.counter.Add(1))

	header := plain[:clearHeaderBytes]
	sealed := c.aead.Seal(nil, iv, plain[clearHeaderBytes:], header)
	out := make([]byte, 0, len(header)+len(sealed)+len(iv)+2)
	out = append(out, header...)
	out = append(out, sealed...)
	out = append(out, iv...)
	out = append(out, byte(len(iv)), frameE2EEKeyIndex)
	return out, nil
}

func (c *testFrameCryptor) decryptFrame(encrypted []byte, clearHeaderBytes int) ([]byte, error) {
	if c == nil || clearHeaderBytes < 0 || len(encrypted) < clearHeaderBytes+testFrameE2EETagBytes+testFrameE2EEIVBytes+2 {
		return nil, errors.New("encrypted frame is too small")
	}
	ivLength := int(encrypted[len(encrypted)-2])
	keyIndex := encrypted[len(encrypted)-1]
	if ivLength != testFrameE2EEIVBytes || keyIndex != frameE2EEKeyIndex {
		return nil, errors.New("unsupported encrypted frame trailer")
	}
	ivStart := len(encrypted) - 2 - ivLength
	if ivStart <= clearHeaderBytes {
		return nil, errors.New("encrypted frame has invalid boundaries")
	}
	header := encrypted[:clearHeaderBytes]
	plainBody, err := c.aead.Open(nil, encrypted[ivStart:len(encrypted)-2], encrypted[clearHeaderBytes:ivStart], header)
	if err != nil {
		return nil, fmt.Errorf("authenticate encrypted frame: %w", err)
	}
	out := make([]byte, 0, len(header)+len(plainBody))
	out = append(out, header...)
	out = append(out, plainBody...)
	return out, nil
}

func vp8ClearHeaderBytes(frame []byte) (int, error) {
	if len(frame) < 3 {
		return 0, errors.New("VP8 frame is too small")
	}
	if frame[0]&0x01 == 0 {
		if len(frame) < 10 {
			return 0, errors.New("VP8 key frame is too small")
		}
		return 10, nil
	}
	return 3, nil
}

func stripVP8PayloadDescriptor(payload []byte) ([]byte, error) {
	if len(payload) < 1 {
		return nil, errors.New("VP8 RTP payload is empty")
	}
	index := 1
	if payload[0]&0x80 != 0 {
		if len(payload) <= index {
			return nil, errors.New("VP8 extension byte is missing")
		}
		extension := payload[index]
		index++
		if extension&0x80 != 0 {
			if len(payload) <= index {
				return nil, errors.New("VP8 picture ID is missing")
			}
			if payload[index]&0x80 != 0 {
				index += 2
			} else {
				index++
			}
		}
		if extension&0x40 != 0 {
			index++
		}
		if extension&0x30 != 0 {
			index++
		}
	}
	if index >= len(payload) {
		return nil, errors.New("VP8 payload descriptor consumes the packet")
	}
	return payload[index:], nil
}

func TestFrameE2EEWireFormatRejectsTampering(t *testing.T) {
	secretBytes := bytes.Repeat([]byte{0x5a}, testFrameE2EESecretBytes)
	cryptor, err := newTestFrameCryptor(base64.RawURLEncoding.EncodeToString(secretBytes))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("symposium-authenticated-frame")
	encrypted, err := cryptor.encryptFrame(plain, 3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted[3:], plain[3:]) {
		t.Fatal("ciphertext contains the plaintext frame body")
	}
	decrypted, err := cryptor.decryptFrame(encrypted, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("decrypted frame = %x, want %x", decrypted, plain)
	}

	tampered := append([]byte(nil), encrypted...)
	tampered[4] ^= 0x80
	if _, err := cryptor.decryptFrame(tampered, 3); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}
