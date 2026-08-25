package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

const androidMediaE2EEnabledEnv = "SYMPOSIUM_ANDROID_MEDIA_E2E"

// TestAndroidClientMediaE2EPeer is the host half of the Android instrumentation
// test. The runner starts it against a standalone relay before launching the app.
// It publishes deterministic encrypted audio/video and authenticates the media
// that Android sends back through the same relay.
func TestAndroidClientMediaE2EPeer(t *testing.T) {
	if os.Getenv(androidMediaE2EEnabledEnv) != "1" {
		t.Skip("host peer is started by scripts/android-media-e2e.sh")
	}

	wsURL := strings.TrimSpace(os.Getenv("SYMPOSIUM_ANDROID_E2E_WS_URL"))
	room := strings.TrimSpace(os.Getenv("SYMPOSIUM_ANDROID_E2E_ROOM"))
	moderatorKey := strings.TrimSpace(os.Getenv("SYMPOSIUM_ANDROID_E2E_MODERATOR_KEY"))
	e2eeSecret := strings.TrimSpace(os.Getenv("SYMPOSIUM_ANDROID_E2E_SECRET"))
	requireOutboundAudio := strings.TrimSpace(os.Getenv("SYMPOSIUM_ANDROID_E2E_REQUIRE_OUTBOUND_AUDIO")) != "false"
	if wsURL == "" || room == "" || moderatorKey == "" || e2eeSecret == "" {
		t.Fatal("Android E2E host peer requires websocket URL, room, moderator key, and E2EE secret")
	}
	frameCryptor, err := newTestFrameCryptor(e2eeSecret)
	if err != nil {
		t.Fatalf("initialize host frame cryptor: %v", err)
	}

	// The runner creates an ephemeral self-signed certificate. Android validates
	// its SPKI pin; this host-side peer only needs encryption for the local test.
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 -- isolated, ephemeral E2E relay
	}}}
	peer := newMediaE2EClientWithDialOptions(t, wsURL, true, &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	peer.acceptAnyPayload.Store(true)
	peer.frameCryptor = frameCryptor
	t.Cleanup(peer.close)

	peer.joinRoom(t, room, moderatorKey, "host-media-peer")
	peer.waitForJoin(t)
	stopMedia := peer.startPublishing(t)
	t.Cleanup(stopMedia)

	// The shell runner waits for this marker before starting instrumentation.
	fmt.Println("ANDROID_MEDIA_E2E_PEER_READY")

	requiredKinds := map[webrtc.RTPCodecType]bool{webrtc.RTPCodecTypeVideo: true}
	if requireOutboundAudio {
		requiredKinds[webrtc.RTPCodecTypeAudio] = true
	}
	received := make(map[webrtc.RTPCodecType]mediaE2EReceipt)
	deadline := time.NewTimer(180 * time.Second)
	defer deadline.Stop()

	for len(received) < len(requiredKinds) {
		select {
		case receipt := <-peer.received:
			if requiredKinds[receipt.kind] {
				received[receipt.kind] = receipt
			}
		case err := <-peer.errs:
			t.Fatalf("Android E2E host peer failed: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for authenticated Android RTP; required=%v received=%v", requiredKinds, received)
		}
	}

	for kind := range requiredKinds {
		if got := received[kind].packets; got < 5 {
			t.Errorf("authenticated Android %s frames = %d, want at least 5", kind.String(), got)
		}
		if got := received[kind].authenticatedFrames; got < 5 {
			t.Errorf("decrypted Android %s frames = %d, want at least 5", kind.String(), got)
		}
	}

	// Keep publishing after the first authenticated Android video frame.
	// The video writer echoes that real VP8 frame back under the conference key,
	// allowing Android to prove the receive/decrypt path before this peer closes.
	time.Sleep(10 * time.Second)
}
