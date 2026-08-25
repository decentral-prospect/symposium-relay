package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
)

const (
	mediaE2ERoom         = "media-e2e"
	mediaE2EModeratorKey = "media-e2e-moderator-key"
)

var (
	// RFC 6716-compatible Opus silence. Using a real encoded frame matters for
	// Android because FrameCryptor runs after codec depacketization.
	mediaE2EAudioPayload = []byte{0xf8, 0xff, 0xfe}
	mediaE2EVideoPayload = []byte("symposium-e2e-video")
)

type mediaE2EReceipt struct {
	kind                webrtc.RTPCodecType
	packets             int
	authenticatedFrames int
}

type mediaE2EClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	ws     *websocket.Conn

	writeMu sync.Mutex
	pcMu    sync.RWMutex
	queueMu sync.Mutex
	echoMu  sync.RWMutex

	publishPC   *webrtc.PeerConnection
	subscribePC *webrtc.PeerConnection

	pendingPublish   []webrtc.ICECandidateInit
	pendingSubscribe map[uint64][]webrtc.ICECandidateInit
	subGeneration    atomic.Uint64
	closed           atomic.Bool
	acceptAnyPayload atomic.Bool
	frameCryptor     *testFrameCryptor
	echoVideoFrame   []byte

	joined   chan signalMsg
	received chan mediaE2EReceipt
	errs     chan error
}

func TestLoopbackICECandidatesRequireExplicitOptIn(t *testing.T) {
	loopback := "candidate:1 1 udp 2130706431 127.0.0.1 40000 typ host"
	private := "candidate:2 1 udp 2130706431 10.0.0.10 40001 typ host"

	if shouldSendICECandidateWithLoopback(loopback, false) {
		t.Fatal("loopback candidate passed without explicit opt-in")
	}
	if !shouldSendICECandidateWithLoopback(loopback, true) {
		t.Fatal("loopback candidate was rejected with explicit opt-in")
	}
	if shouldSendICECandidateWithLoopback(private, true) {
		t.Fatal("private candidate passed when only loopback was enabled")
	}
	if !shouldSendICECandidateWithPolicy(private, false, true) {
		t.Fatal("private candidate was rejected with explicit private ICE opt-in")
	}
}

func TestMediaTrafficE2EAudioAndVideo(t *testing.T) {
	relay := newMediaE2ERelay(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", relay.wsHandler)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws"
	subscriber := newMediaE2EClient(t, wsURL, true)
	t.Cleanup(subscriber.close)
	publisher := newMediaE2EClient(t, wsURL, false)
	t.Cleanup(publisher.close)

	subscriber.join(t, "subscriber")
	subscriber.waitForJoin(t)
	publisher.join(t, "publisher")
	publisher.waitForJoin(t)

	stopMedia := publisher.startPublishing(t)
	t.Cleanup(stopMedia)

	receipts := make(map[webrtc.RTPCodecType]mediaE2EReceipt)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()

	for len(receipts) < 2 {
		select {
		case receipt := <-subscriber.received:
			receipts[receipt.kind] = receipt
		case err := <-subscriber.errs:
			t.Fatalf("subscriber failed: %v", err)
		case err := <-publisher.errs:
			t.Fatalf("publisher failed: %v", err)
		case <-deadline.C:
			t.Fatalf("timed out waiting for relayed audio and video; received=%v", receipts)
		}
	}

	for _, kind := range []webrtc.RTPCodecType{webrtc.RTPCodecTypeAudio, webrtc.RTPCodecTypeVideo} {
		receipt := receipts[kind]
		if receipt.packets < 5 {
			t.Errorf("relayed %s packets = %d, want at least 5", kind.String(), receipt.packets)
		}
	}
}

func newMediaE2ERelay(t *testing.T) *server {
	t.Helper()

	return &server{
		api:                        newMediaE2EAPI(t),
		config:                     mediaE2EConfiguration(),
		allowLoopbackICECandidates: true,
		rooms:                      make(map[string]*room),
		openRooms: map[string]string{
			mediaE2ERoom: mediaE2EModeratorKey,
		},
	}
}

func newMediaE2EAPI(t *testing.T) *webrtc.API {
	t.Helper()

	var mediaEngine webrtc.MediaEngine
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("register WebRTC codecs: %v", err)
	}

	interceptors := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(&mediaEngine, interceptors); err != nil {
		t.Fatalf("register WebRTC interceptors: %v", err)
	}

	settings := webrtc.SettingEngine{}
	settings.SetIncludeLoopbackCandidate(true)
	// Android's encoder can produce RTP datagrams above Pion's conservative
	// default receive buffer while running over a local, jumbo-capable path.
	settings.SetReceiveMTU(64 * 1024)

	return webrtc.NewAPI(
		webrtc.WithMediaEngine(&mediaEngine),
		webrtc.WithInterceptorRegistry(interceptors),
		webrtc.WithSettingEngine(settings),
	)
}

func mediaE2EConfiguration() webrtc.Configuration {
	return webrtc.Configuration{
		BundlePolicy:  webrtc.BundlePolicyMaxBundle,
		RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
	}
}

func newMediaE2EClient(t *testing.T, wsURL string, receiveMedia bool) *mediaE2EClient {
	return newMediaE2EClientWithDialOptions(t, wsURL, receiveMedia, nil)
}

func newMediaE2EClientWithDialOptions(t *testing.T, wsURL string, receiveMedia bool, options *websocket.DialOptions) *mediaE2EClient {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	conn, _, err := websocket.Dial(ctx, wsURL, options)
	if err != nil {
		cancel()
		t.Fatalf("dial relay websocket: %v", err)
	}

	client := &mediaE2EClient{
		ctx:              ctx,
		cancel:           cancel,
		ws:               conn,
		pendingSubscribe: make(map[uint64][]webrtc.ICECandidateInit),
		joined:           make(chan signalMsg, 1),
		received:         make(chan mediaE2EReceipt, 2),
		errs:             make(chan error, 16),
	}

	if receiveMedia {
		pc, err := newMediaE2EAPI(t).NewPeerConnection(mediaE2EConfiguration())
		if err != nil {
			client.close()
			t.Fatalf("create subscriber peer connection: %v", err)
		}
		client.subscribePC = pc
		client.bindSubscribePeerConnection()
	}

	go client.readSignals()
	return client
}

func (c *mediaE2EClient) join(t *testing.T, username string) {
	c.joinRoom(t, mediaE2ERoom, mediaE2EModeratorKey, username)
}

func (c *mediaE2EClient) joinRoom(t *testing.T, room string, moderatorKey string, username string) {
	t.Helper()

	if err := c.write(signalMsg{
		Type:     "join",
		Room:     room,
		Username: username,
		ClientID: "media-e2e-" + username,
		ModKey:   moderatorKey,
	}); err != nil {
		t.Fatalf("join %s: %v", username, err)
	}
}

func (c *mediaE2EClient) waitForJoin(t *testing.T) signalMsg {
	t.Helper()

	select {
	case msg := <-c.joined:
		if msg.Role != roleModerator {
			t.Fatalf("joined with role %q, want %q", msg.Role, roleModerator)
		}
		return msg
	case err := <-c.errs:
		t.Fatalf("join failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for join acknowledgement")
	}
	return signalMsg{}
}

func (c *mediaE2EClient) bindSubscribePeerConnection() {
	c.subscribePC.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil || c.closed.Load() {
			return
		}
		generation := c.subGeneration.Load()
		if generation == 0 {
			c.reportError(errors.New("subscriber gathered ICE before receiving a generation"))
			return
		}
		jsonCandidate := candidate.ToJSON()
		if err := c.write(signalMsg{
			Type:       "trickle",
			Target:     "subscribe",
			Generation: generation,
			Candidate:  &jsonCandidate,
		}); err != nil {
			c.reportError(fmt.Errorf("send subscribe ICE: %w", err))
		}
	})

	c.subscribePC.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		go c.readRelayedTrack(track)
	})
}

func (c *mediaE2EClient) readRelayedTrack(track *webrtc.TrackRemote) {
	if c.acceptAnyPayload.Load() {
		c.readRawRelayedTrack(track)
		return
	}

	wantPayload := mediaE2EVideoPayload
	if track.Kind() == webrtc.RTPCodecTypeAudio {
		wantPayload = mediaE2EAudioPayload
	}

	matchingPackets := 0
	for {
		packet, _, err := track.ReadRTP()
		if err != nil {
			if c.ctx.Err() == nil && !c.closed.Load() {
				c.reportError(fmt.Errorf("read relayed %s RTP: %w", track.Kind().String(), err))
			}
			return
		}
		if !bytes.Equal(packet.Payload, wantPayload) {
			continue
		}
		matchingPackets++
		if matchingPackets == 5 {
			select {
			case c.received <- mediaE2EReceipt{kind: track.Kind(), packets: matchingPackets}:
			case <-c.ctx.Done():
			}
			return
		}
	}
}

func (c *mediaE2EClient) readRawRelayedTrack(track *webrtc.TrackRemote) {
	if c.frameCryptor != nil {
		c.readEncryptedRawRelayedTrack(track)
		return
	}

	buffer := make([]byte, 64*1024)
	packets := 0
	for {
		n, _, err := track.Read(buffer)
		if err != nil {
			if c.ctx.Err() == nil && !c.closed.Load() {
				c.reportError(fmt.Errorf("read raw relayed %s RTP: %w", track.Kind().String(), err))
			}
			return
		}
		if n == 0 {
			continue
		}
		packets++
		if packets == 5 {
			select {
			case c.received <- mediaE2EReceipt{kind: track.Kind(), packets: packets}:
			case <-c.ctx.Done():
			}
			return
		}
	}
}

func (c *mediaE2EClient) readEncryptedRawRelayedTrack(track *webrtc.TrackRemote) {
	authenticatedFrames := 0
	var videoTimestamp uint32
	var videoFrame []byte

	for {
		packet, _, readErr := track.ReadRTP()
		if readErr != nil {
			if c.ctx.Err() == nil && !c.closed.Load() {
				c.reportError(fmt.Errorf("read encrypted %s RTP: %w", track.Kind().String(), readErr))
			}
			return
		}
		timestamp := packet.Timestamp
		marker := packet.Marker
		payload := packet.Payload

		if track.Kind() == webrtc.RTPCodecTypeAudio {
			plain, decryptErr := c.frameCryptor.decryptFrame(payload, 1)
			if decryptErr != nil {
				c.reportError(fmt.Errorf("authenticate Android audio frame: %w", decryptErr))
				return
			}
			if len(plain) <= 1 {
				c.reportError(errors.New("decrypted Android audio frame is empty"))
				return
			}
			authenticatedFrames++
		} else {
			codecPayload, descriptorErr := stripVP8PayloadDescriptor(payload)
			if descriptorErr != nil {
				c.reportError(fmt.Errorf("parse Android VP8 descriptor: %w", descriptorErr))
				return
			}
			if videoTimestamp != 0 && timestamp != videoTimestamp {
				videoFrame = videoFrame[:0]
			}
			videoTimestamp = timestamp
			videoFrame = append(videoFrame, codecPayload...)
			if !marker {
				continue
			}
			headerBytes, headerErr := vp8ClearHeaderBytes(videoFrame)
			if headerErr != nil {
				c.reportError(fmt.Errorf("inspect Android VP8 frame: %w", headerErr))
				return
			}
			plain, decryptErr := c.frameCryptor.decryptFrame(videoFrame, headerBytes)
			if decryptErr != nil {
				c.reportError(fmt.Errorf("authenticate Android video frame: %w", decryptErr))
				return
			}
			if len(plain) <= headerBytes {
				c.reportError(errors.New("decrypted Android video frame is empty"))
				return
			}
			c.storeEchoVideoFrame(plain)
			authenticatedFrames++
			videoFrame = videoFrame[:0]
		}

		if authenticatedFrames == 5 {
			select {
			case c.received <- mediaE2EReceipt{
				kind:                track.Kind(),
				packets:             authenticatedFrames,
				authenticatedFrames: authenticatedFrames,
			}:
			case <-c.ctx.Done():
			}
			return
		}
	}
}

func (c *mediaE2EClient) startPublishing(t *testing.T) func() {
	t.Helper()

	api := newMediaE2EAPI(t)
	pc, err := api.NewPeerConnection(mediaE2EConfiguration())
	if err != nil {
		t.Fatalf("create publisher peer connection: %v", err)
	}
	c.pcMu.Lock()
	c.publishPC = pc
	c.pcMu.Unlock()

	audioTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType:  webrtc.MimeTypeOpus,
		ClockRate: 48000,
		Channels:  2,
	}, "audio-e2e", "publisher-e2e")
	if err != nil {
		t.Fatalf("create audio track: %v", err)
	}
	videoTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType:  webrtc.MimeTypeVP8,
		ClockRate: 90000,
	}, "video-e2e", "publisher-e2e")
	if err != nil {
		t.Fatalf("create video track: %v", err)
	}

	for _, track := range []*webrtc.TrackLocalStaticRTP{audioTrack, videoTrack} {
		sender, addErr := pc.AddTrack(track)
		if addErr != nil {
			t.Fatalf("add publish track: %v", addErr)
		}
		go drainMediaE2ERTCP(c.ctx, sender)
	}

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil || c.closed.Load() {
			return
		}
		jsonCandidate := candidate.ToJSON()
		if writeErr := c.write(signalMsg{
			Type:      "trickle",
			Target:    "publish",
			Candidate: &jsonCandidate,
		}); writeErr != nil {
			c.reportError(fmt.Errorf("send publish ICE: %w", writeErr))
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create publish offer: %v", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatalf("set publish offer: %v", err)
	}
	if err := c.write(signalMsg{
		Type:   "publishOffer",
		Target: "publish",
		SDP:    pc.LocalDescription(),
	}); err != nil {
		t.Fatalf("send publish offer: %v", err)
	}

	mediaCtx, stopMedia := context.WithCancel(c.ctx)
	if c.frameCryptor != nil {
		go writeFrameEncryptedMediaE2ERTP(
			mediaCtx,
			audioTrack,
			20*time.Millisecond,
			960,
			mediaE2EAudioPayload,
			1,
			false,
			c.frameCryptor,
		)
		go c.writeEchoedEncryptedVideoE2ERTP(mediaCtx, videoTrack)
	} else {
		go writeMediaE2ERTP(mediaCtx, audioTrack, 20*time.Millisecond, 960, mediaE2EAudioPayload)
		go writeMediaE2ERTP(mediaCtx, videoTrack, 33*time.Millisecond, 3000, mediaE2EVideoPayload)
	}
	return stopMedia
}

func (c *mediaE2EClient) storeEchoVideoFrame(frame []byte) {
	c.echoMu.Lock()
	c.echoVideoFrame = append(c.echoVideoFrame[:0], frame...)
	c.echoMu.Unlock()
}

func (c *mediaE2EClient) videoFrameForEcho() []byte {
	c.echoMu.RLock()
	defer c.echoMu.RUnlock()
	if len(c.echoVideoFrame) == 0 {
		return append([]byte(nil), mediaE2EVideoPayload...)
	}
	return append([]byte(nil), c.echoVideoFrame...)
}

func (c *mediaE2EClient) writeEchoedEncryptedVideoE2ERTP(
	ctx context.Context,
	track *webrtc.TrackLocalStaticRTP,
) {
	ticker := time.NewTicker(33 * time.Millisecond)
	defer ticker.Stop()

	packetizer := rtp.NewPacketizer(
		1200,
		96,
		1,
		&codecs.VP8Payloader{},
		rtp.NewRandomSequencer(),
		90000,
	)
	for {
		select {
		case <-ticker.C:
			plain := c.videoFrameForEcho()
			headerBytes, err := vp8ClearHeaderBytes(plain)
			if err != nil {
				continue
			}
			encrypted, err := c.frameCryptor.encryptFrame(plain, headerBytes)
			if err != nil {
				return
			}
			for _, packet := range packetizer.Packetize(encrypted, 3000) {
				_ = track.WriteRTP(packet)
			}
		case <-ctx.Done():
			return
		}
	}
}

func writeFrameEncryptedMediaE2ERTP(
	ctx context.Context,
	track *webrtc.TrackLocalStaticRTP,
	interval time.Duration,
	timestampStep uint32,
	plain []byte,
	clearHeaderBytes int,
	vp8 bool,
	cryptor *testFrameCryptor,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var sequence uint16
	var timestamp uint32
	for {
		select {
		case <-ticker.C:
			sequence++
			timestamp += timestampStep
			encrypted, err := cryptor.encryptFrame(plain, clearHeaderBytes)
			if err != nil {
				return
			}
			payload := encrypted
			if vp8 {
				// S=1, PartID=0. The descriptor is added by the RTP packetizer and
				// is not part of the encoded frame protected by FrameCryptor.
				payload = append([]byte{0x10}, encrypted...)
			}
			_ = track.WriteRTP(&rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: sequence,
					Timestamp:      timestamp,
				},
				Payload: payload,
			})
		case <-ctx.Done():
			return
		}
	}
}

func writeMediaE2ERTP(ctx context.Context, track *webrtc.TrackLocalStaticRTP, interval time.Duration, timestampStep uint32, payload []byte) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var sequence uint16
	var timestamp uint32
	for {
		select {
		case <-ticker.C:
			sequence++
			timestamp += timestampStep
			_ = track.WriteRTP(&rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					SequenceNumber: sequence,
					Timestamp:      timestamp,
				},
				Payload: payload,
			})
		case <-ctx.Done():
			return
		}
	}
}

func drainMediaE2ERTCP(ctx context.Context, sender *webrtc.RTPSender) {
	for {
		if _, _, err := sender.ReadRTCP(); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (c *mediaE2EClient) readSignals() {
	for {
		var msg signalMsg
		if err := wsjson.Read(c.ctx, c.ws, &msg); err != nil {
			if c.ctx.Err() == nil && !c.closed.Load() && websocket.CloseStatus(err) == -1 {
				c.reportError(fmt.Errorf("read signaling: %w", err))
			}
			return
		}

		switch msg.Type {
		case "join":
			select {
			case c.joined <- msg:
			default:
			}
		case "publishAnswer":
			if err := c.applyPublishAnswer(msg); err != nil {
				c.reportError(err)
			}
		case "subscribeOffer":
			if err := c.answerSubscribeOffer(msg); err != nil {
				c.reportError(err)
			}
		case "trickle":
			if err := c.applyRemoteCandidate(msg); err != nil {
				c.reportError(err)
			}
		case "error":
			c.reportError(fmt.Errorf("relay error: %s", msg.Error))
		}
	}
}

func (c *mediaE2EClient) applyPublishAnswer(msg signalMsg) error {
	if msg.SDP == nil {
		return errors.New("publish answer has no SDP")
	}
	c.pcMu.RLock()
	pc := c.publishPC
	c.pcMu.RUnlock()
	if pc == nil {
		return errors.New("publish answer arrived without a publish peer connection")
	}
	if err := pc.SetRemoteDescription(*msg.SDP); err != nil {
		return fmt.Errorf("set publish answer: %w", err)
	}
	return c.flushRemoteCandidates("publish", 0, pc)
}

func (c *mediaE2EClient) answerSubscribeOffer(msg signalMsg) error {
	if msg.SDP == nil {
		return errors.New("subscribe offer has no SDP")
	}
	if msg.Generation == 0 {
		return errors.New("subscribe offer has no generation")
	}
	c.pcMu.RLock()
	pc := c.subscribePC
	c.pcMu.RUnlock()
	if pc == nil {
		return errors.New("subscribe offer arrived without a subscribe peer connection")
	}

	c.subGeneration.Store(msg.Generation)
	if err := pc.SetRemoteDescription(*msg.SDP); err != nil {
		return fmt.Errorf("set subscribe offer: %w", err)
	}
	if err := c.flushRemoteCandidates("subscribe", msg.Generation, pc); err != nil {
		return err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create subscribe answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set subscribe answer: %w", err)
	}
	if err := c.write(signalMsg{
		Type:       "subscribeAnswer",
		Target:     "subscribe",
		Generation: msg.Generation,
		Revision:   msg.Revision,
		SDP:        pc.LocalDescription(),
	}); err != nil {
		return fmt.Errorf("send subscribe answer: %w", err)
	}
	return nil
}

func (c *mediaE2EClient) applyRemoteCandidate(msg signalMsg) error {
	if msg.Candidate == nil || strings.TrimSpace(msg.Candidate.Candidate) == "" {
		return nil
	}

	c.pcMu.RLock()
	var pc *webrtc.PeerConnection
	switch msg.Target {
	case "publish":
		pc = c.publishPC
	case "subscribe":
		pc = c.subscribePC
	default:
		c.pcMu.RUnlock()
		return fmt.Errorf("unknown ICE target %q", msg.Target)
	}
	c.pcMu.RUnlock()

	if pc == nil || pc.RemoteDescription() == nil {
		c.queueRemoteCandidate(msg.Target, msg.Generation, *msg.Candidate)
		return nil
	}
	if msg.Target == "subscribe" && msg.Generation != c.subGeneration.Load() {
		c.queueRemoteCandidate(msg.Target, msg.Generation, *msg.Candidate)
		return nil
	}
	if err := pc.AddICECandidate(*msg.Candidate); err != nil {
		return fmt.Errorf("add %s ICE candidate: %w", msg.Target, err)
	}
	return nil
}

func (c *mediaE2EClient) queueRemoteCandidate(target string, generation uint64, candidate webrtc.ICECandidateInit) {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	if target == "publish" {
		c.pendingPublish = append(c.pendingPublish, candidate)
		return
	}
	c.pendingSubscribe[generation] = append(c.pendingSubscribe[generation], candidate)
}

func (c *mediaE2EClient) flushRemoteCandidates(target string, generation uint64, pc *webrtc.PeerConnection) error {
	c.queueMu.Lock()
	var candidates []webrtc.ICECandidateInit
	if target == "publish" {
		candidates = c.pendingPublish
		c.pendingPublish = nil
	} else {
		candidates = c.pendingSubscribe[generation]
		delete(c.pendingSubscribe, generation)
	}
	c.queueMu.Unlock()

	for _, candidate := range candidates {
		if err := pc.AddICECandidate(candidate); err != nil {
			return fmt.Errorf("flush %s ICE candidate: %w", target, err)
		}
	}
	return nil
}

func (c *mediaE2EClient) write(msg signalMsg) error {
	if c.closed.Load() {
		return errors.New("client is closed")
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return wsjson.Write(ctx, c.ws, msg)
}

func (c *mediaE2EClient) reportError(err error) {
	if err == nil || c.closed.Load() {
		return
	}
	select {
	case c.errs <- err:
	default:
	}
}

func (c *mediaE2EClient) close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	c.cancel()
	_ = c.ws.CloseNow()

	c.pcMu.Lock()
	publishPC := c.publishPC
	subscribePC := c.subscribePC
	c.publishPC = nil
	c.subscribePC = nil
	c.pcMu.Unlock()

	if publishPC != nil {
		_ = publishPC.Close()
	}
	if subscribePC != nil {
		_ = subscribePC.Close()
	}
}
