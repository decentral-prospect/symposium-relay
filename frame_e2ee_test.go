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

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
	"golang.org/x/crypto/pbkdf2"
)

const (
	testFrameE2EESecretBytes = 32
	testFrameE2EEIVBytes     = 12
	testFrameE2EETagBytes    = 16
	frameE2EEKeyIndex        = byte(0)
)

var testFrameE2EERatchetSalt = []byte("SymposiumFrameEncryptionKey/v1")

func newE2EVideoSampleBuilder() *samplebuilder.SampleBuilder {
	return samplebuilder.New(128, &codecs.VP8Packet{}, 90000)
}

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

func TestE2EVideoAssemblyAuthenticatesCompleteFrames(t *testing.T) {
	cryptor, err := newTestFrameCryptor(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{0x11, 0, 0}, bytes.Repeat([]byte{0x42}, 1024)...)
	encrypted, err := cryptor.encryptFrame(plain, 3)
	if err != nil {
		t.Fatal(err)
	}
	fragments := (&codecs.VP8Payloader{}).Payload(120, encrypted)
	for _, scenario := range []string{"ordered", "join-mid-frame", "missing-fragment", "reordered", "duplicate", "sequence-wrap", "tampered"} {
		t.Run(scenario, func(t *testing.T) {
			builder := newE2EVideoSampleBuilder()
			var packets []*rtp.Packet
			sequence := uint16(100)
			if scenario == "sequence-wrap" {
				sequence = 65532
			}
			frameCount := 2
			if scenario == "missing-fragment" {
				// Keep the stream flowing beyond the reorder window so a lost
				// packet expires and subsequent complete frames can be emitted.
				frameCount = 20
			}
			for frame := 0; frame < frameCount; frame++ {
				for i, fragment := range fragments {
					packet := &rtp.Packet{Header: rtp.Header{
						Version: 2, SequenceNumber: sequence, Timestamp: uint32(3000 * (frame + 1)), Marker: i == len(fragments)-1,
					}, Payload: append([]byte(nil), fragment...)}
					sequence++
					if frame == 0 && ((scenario == "join-mid-frame" && i == 0) || (scenario == "missing-fragment" && i == 2)) {
						continue
					}
					if scenario == "tampered" && frame == 0 && i == 2 {
						packet.Payload[2] ^= 0x80
					}
					packets = append(packets, packet)
					if scenario == "duplicate" {
						packets = append(packets, packet.Clone())
					}
				}
			}
			if scenario == "reordered" {
				packets[1], packets[2] = packets[2], packets[1]
			}
			authenticated, rejected := 0, 0
			drain := func() {
				for sample := builder.Pop(); sample != nil; sample = builder.Pop() {
					decoded, err := cryptor.decryptFrame(sample.Data, 3)
					if err != nil {
						rejected++
						continue
					}
					if !bytes.Equal(decoded, plain) {
						t.Fatal("assembled frame differs from the authenticated original")
					}
					authenticated++
				}
			}
			for _, packet := range packets {
				builder.Push(packet)
				drain()
			}
			builder.Flush()
			drain()
			wantAuthenticated, wantRejected := frameCount, 0
			if scenario == "join-mid-frame" || scenario == "missing-fragment" || scenario == "tampered" {
				wantAuthenticated--
			}
			if scenario == "tampered" {
				wantRejected = 1
			}
			if authenticated != wantAuthenticated || rejected != wantRejected {
				t.Fatalf("authenticated=%d rejected=%d; want %d and %d", authenticated, rejected, wantAuthenticated, wantRejected)
			}
		})
	}
}
