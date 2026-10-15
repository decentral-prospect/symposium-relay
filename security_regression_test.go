package main

import (
	"context"
	"encoding/json"
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
	"github.com/pion/webrtc/v4"
)

func TestDefaultRelayLimitsMatchStandardSmallServerProfile(t *testing.T) {
	limits := defaultRelayLimits()
	if limits.MaxActivePeers != 250 || limits.MaxPendingLobbyPeers != 500 {
		t.Fatalf("unexpected peer limits: active=%d lobby=%d", limits.MaxActivePeers, limits.MaxPendingLobbyPeers)
	}
	if limits.PendingICECandidatesPerPeer != 64 || limits.PendingICEBytesPerPeer != 256*1024 {
		t.Fatalf(
			"unexpected per-peer ICE limits: candidates=%d bytes=%d",
			limits.PendingICECandidatesPerPeer,
			limits.PendingICEBytesPerPeer,
		)
	}
	if limits.PendingICEBytesTotal != 16*1024*1024 || limits.MaxConcurrentJoins != 16 {
		t.Fatalf(
			"unexpected relay budgets: pendingICE=%d concurrentJoins=%d",
			limits.PendingICEBytesTotal,
			limits.MaxConcurrentJoins,
		)
	}
	if limits.MaxPreJoinConnections != 512 || limits.MaxPreJoinConnectionsPerIP != 32 || limits.PreJoinTimeout != 15*time.Second {
		t.Fatalf("unexpected pre-join limits: total=%d perIP=%d timeout=%s", limits.MaxPreJoinConnections, limits.MaxPreJoinConnectionsPerIP, limits.PreJoinTimeout)
	}
}

func TestPreJoinConnectionsAreBoundedGloballyAndPerIP(t *testing.T) {
	s := &server{
		limits: relayLimits{
			MaxPreJoinConnections:      2,
			MaxPreJoinConnectionsPerIP: 1,
			PreJoinTimeout:             time.Second,
		},
		preJoinByIP: make(map[string]int),
	}
	if !s.reservePreJoin("192.0.2.1") {
		t.Fatal("first pre-join reservation was rejected")
	}
	if s.reservePreJoin("192.0.2.1") {
		t.Fatal("per-IP pre-join limit was not enforced")
	}
	if !s.reservePreJoin("192.0.2.2") {
		t.Fatal("second source IP was rejected before the global limit")
	}
	if s.reservePreJoin("192.0.2.3") {
		t.Fatal("global pre-join limit was not enforced")
	}
	p := &peer{preJoinIP: "192.0.2.1"}
	p.preJoinReserved.Store(true)
	s.releasePreJoin(p)
	s.releasePreJoin(p)
	if !s.reservePreJoin("192.0.2.3") {
		t.Fatal("released pre-join capacity was not reusable")
	}
}

func TestAdminRoutesNeverReceiveWildcardCORS(t *testing.T) {
	handler := hWithCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/admin/version", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("admin CORS origin = %q, want empty", got)
	}
	if got := response.Header().Get("Access-Control-Allow-Headers"); got != "" {
		t.Fatalf("admin CORS headers = %q, want empty", got)
	}
}

func TestInvalidRoomAndInvalidInstanceHaveIndistinguishableJoinErrors(t *testing.T) {
	s := &server{
		openRooms:     map[string]string{"known-room": "moderator-key"},
		roomInstances: map[string]string{"known-room": "known-instance"},
		roomVersions:  map[string]string{"known-room": serverVersion},
	}
	joinError := func(roomName string, roomInstance string) signalMsg {
		var response signalMsg
		p := &peer{id: roomName, writeHook: func(value any) { response = value.(signalMsg) }}
		s.handleJoin(context.Background(), p, signalMsg{
			Type:          "join",
			Room:          roomName,
			RoomInstance:  roomInstance,
			ClientVersion: serverVersion,
		})
		return response
	}
	missing := joinError("missing-room", "known-instance")
	stale := joinError("known-room", "stale-instance")
	if missing.Code != "invitation-invalid" || missing.Code != stale.Code || missing.Error != stale.Error {
		t.Fatalf("enumerable join errors: missing=%+v stale=%+v", missing, stale)
	}
}

func TestLobbyWaitDoesNotExposeRoomMutePolicy(t *testing.T) {
	s := &server{
		limits:        relayLimits{MaxPendingLobbyPeers: 10, JoinRatePerMinute: 10, MaxConcurrentJoins: 2},
		rooms:         make(map[string]*room),
		openRooms:     map[string]string{"room": "moderator-key"},
		roomInstances: map[string]string{"room": "known-instance"},
		roomVersions:  map[string]string{"room": serverVersion},
		settings:      map[string]roomSettings{"room": {MuteAllByDefault: true}},
	}
	var response signalMsg
	p := &peer{id: "guest", writeHook: func(value any) { response = value.(signalMsg) }}
	s.handleJoin(context.Background(), p, signalMsg{Type: "join", Room: "room", RoomInstance: "known-instance", ClientVersion: serverVersion})
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal lobby response: %v", err)
	}
	if strings.Contains(string(raw), "muteAll") {
		t.Fatalf("lobby response leaked room policy: %s", raw)
	}
	s.detachPeer(p, "test complete")
}

func securityTestRoom() *room {
	return &room{
		name:      "security-test-room",
		instance:  "security-test-instance",
		peers:     make(map[string]*peer),
		pending:   make(map[string]*peer),
		pubs:      make(map[string]*publication),
		muteAllow: make(map[string]bool),
		muted:     make(map[string]bool),
	}
}

func TestPendingICEAuditFloodIsBounded(t *testing.T) {
	s := &server{limits: relayLimits{
		PendingICECandidatesPerPeer: 32,
		PendingICEBytesPerPeer:      64 * 1024,
		PendingICEBytesTotal:        128 * 1024,
	}}
	r := securityTestRoom()
	p := &peer{id: "admitted-peer", room: r, role: roleGuest}
	r.peers[p.id] = p

	limitErrors := 0
	p.writeHook = func(value any) {
		msg, ok := value.(signalMsg)
		if ok && msg.Code == "pending-ice-limit" {
			limitErrors++
		}
	}
	candidate := webrtc.ICECandidateInit{Candidate: "candidate:" + strings.Repeat("x", 1000)}
	for i := 0; i < 10000; i++ {
		s.handleTrickle(context.Background(), p, signalMsg{
			Type:      "trickle",
			Target:    "publish",
			Candidate: &candidate,
		})
	}

	p.candMu.Lock()
	count := p.pendingCandidateCount
	retained := p.pendingCandidateBytes
	queued := len(p.pendingPubCandidates) + len(p.pendingSubCandidates)
	p.candMu.Unlock()
	if count != 32 || queued != 32 {
		t.Fatalf("queued candidates = %d (accounted %d), want 32", queued, count)
	}
	if retained > s.effectiveLimits().PendingICEBytesPerPeer {
		t.Fatalf("peer retained bytes = %d, limit = %d", retained, s.effectiveLimits().PendingICEBytesPerPeer)
	}
	if got := s.pendingICEBytes.Load(); got != retained {
		t.Fatalf("relay retained bytes = %d, peer retained bytes = %d", got, retained)
	}
	if limitErrors == 0 {
		t.Fatal("candidate flood did not produce a pending-ice-limit protocol error")
	}

	s.detachPeer(p, "test complete")
	if got := s.pendingICEBytes.Load(); got != 0 {
		t.Fatalf("relay retained bytes after disconnect = %d, want 0", got)
	}
}

func TestPendingICEBudgetIsSharedAcrossPublishSubscribeAndPeers(t *testing.T) {
	const relayBudget = int64(256 * 1024)
	s := &server{limits: relayLimits{
		PendingICECandidatesPerPeer: 128,
		PendingICEBytesPerPeer:      64 * 1024,
		PendingICEBytesTotal:        relayBudget,
	}}
	candidate := webrtc.ICECandidateInit{Candidate: "candidate:" + strings.Repeat("y", 2000)}
	peers := make([]*peer, 0, 1000)
	rejected := 0
	for i := 0; i < 1000; i++ {
		p := &peer{id: fmt.Sprintf("peer-%d", i)}
		peers = append(peers, p)
		for n := 0; n < 8; n++ {
			target := "publish"
			if n%2 == 1 {
				target = "subscribe"
			}
			if err := s.queueCandidate(p, target, 1, candidate); err != nil {
				rejected++
			}
		}
	}

	var aggregate int64
	for _, p := range peers {
		p.candMu.Lock()
		aggregate += p.pendingCandidateBytes
		if p.pendingCandidateCount > s.effectiveLimits().PendingICECandidatesPerPeer {
			t.Fatalf("peer %s exceeded candidate count", p.id)
		}
		if p.pendingCandidateBytes > s.effectiveLimits().PendingICEBytesPerPeer {
			t.Fatalf("peer %s exceeded retained byte limit", p.id)
		}
		p.candMu.Unlock()
	}
	if aggregate != s.pendingICEBytes.Load() {
		t.Fatalf("aggregate peer bytes = %d, relay counter = %d", aggregate, s.pendingICEBytes.Load())
	}
	if aggregate > relayBudget {
		t.Fatalf("1000 peers retained %d bytes, relay limit = %d", aggregate, relayBudget)
	}
	if rejected == 0 {
		t.Fatal("relay-wide budget did not reject any candidates")
	}

	for _, p := range peers {
		s.detachPeer(p, "test complete")
	}
	if got := s.pendingICEBytes.Load(); got != 0 {
		t.Fatalf("relay retained bytes after all disconnects = %d, want 0", got)
	}
}

func TestPendingICECountersResetWhenNegotiationQueueIsReplaced(t *testing.T) {
	s := &server{limits: relayLimits{
		PendingICECandidatesPerPeer: 8,
		PendingICEBytesPerPeer:      32 * 1024,
		PendingICEBytesTotal:        64 * 1024,
	}}
	p := &peer{id: "renegotiating-peer"}
	candidate := webrtc.ICECandidateInit{Candidate: "candidate:" + strings.Repeat("z", 500)}
	if err := s.queueCandidate(p, "publish", 0, candidate); err != nil {
		t.Fatalf("queue publish candidate: %v", err)
	}
	if err := s.queueCandidate(p, "subscribe", 1, candidate); err != nil {
		t.Fatalf("queue subscribe candidate: %v", err)
	}
	itemBytes := pendingCandidateRetainedBytes(candidate)

	s.clearPendingCandidates(p, "subscribe")
	p.candMu.Lock()
	countAfterSubscribeReset := p.pendingCandidateCount
	bytesAfterSubscribeReset := p.pendingCandidateBytes
	p.candMu.Unlock()
	if countAfterSubscribeReset != 1 || bytesAfterSubscribeReset != itemBytes {
		t.Fatalf("after subscribe reset count=%d bytes=%d, want 1 and %d", countAfterSubscribeReset, bytesAfterSubscribeReset, itemBytes)
	}
	if got := s.pendingICEBytes.Load(); got != itemBytes {
		t.Fatalf("relay bytes after subscribe reset = %d, want %d", got, itemBytes)
	}

	s.clearPendingCandidates(p, "publish")
	if got := s.pendingICEBytes.Load(); got != 0 {
		t.Fatalf("relay bytes after all queues reset = %d, want 0", got)
	}
}

func TestPendingAndActiveCapacityAreIndependent(t *testing.T) {
	s := &server{limits: relayLimits{MaxActivePeers: 2, MaxPendingLobbyPeers: 3}}
	active := []*peer{{id: "active-1"}, {id: "active-2"}}
	pending := []*peer{{id: "pending-1"}, {id: "pending-2"}, {id: "pending-3"}}
	for _, p := range active {
		if !s.reservePeerCapacity(p, capacitySlotActive) {
			t.Fatalf("failed to reserve legitimate active capacity for %s", p.id)
		}
	}
	for _, p := range pending {
		if !s.reservePeerCapacity(p, capacitySlotPending) {
			t.Fatalf("pending lobby incorrectly shared the active capacity limit for %s", p.id)
		}
	}
	if s.reservePeerCapacity(&peer{id: "active-overflow"}, capacitySlotActive) {
		t.Fatal("active capacity overflow was accepted")
	}
	if s.reservePeerCapacity(&peer{id: "pending-overflow"}, capacitySlotPending) {
		t.Fatal("pending lobby capacity overflow was accepted")
	}
}

func TestPendingLobbyCapacityIsReleasedOnDisconnect(t *testing.T) {
	s := &server{
		limits: relayLimits{
			MaxActivePeers:       10,
			MaxPendingLobbyPeers: 2,
			JoinRatePerMinute:    10,
			MaxConcurrentJoins:   2,
		},
		rooms:         make(map[string]*room),
		openRooms:     map[string]string{"room": "moderator-key"},
		roomInstances: map[string]string{"room": "security-test-instance"},
		settings:      make(map[string]roomSettings),
	}
	join := func(id string) (*peer, []signalMsg) {
		messages := make([]signalMsg, 0, 1)
		p := &peer{id: id, role: roleGuest}
		p.writeHook = func(value any) {
			if msg, ok := value.(signalMsg); ok {
				messages = append(messages, msg)
			}
		}
		s.handleJoin(context.Background(), p, signalMsg{Type: "join", Room: "room", RoomInstance: "security-test-instance", Username: id, ClientVersion: serverVersion})
		return p, messages
	}

	first, firstMessages := join("first")
	_, secondMessages := join("second")
	_, overflowMessages := join("overflow")
	if len(firstMessages) == 0 || firstMessages[0].Type != "lobby-wait" {
		t.Fatalf("first peer was not admitted to the lobby: %+v", firstMessages)
	}
	if len(secondMessages) == 0 || secondMessages[0].Type != "lobby-wait" {
		t.Fatalf("second peer was not admitted to the lobby: %+v", secondMessages)
	}
	if len(overflowMessages) == 0 || overflowMessages[0].Code != "lobby-capacity" {
		t.Fatalf("lobby overflow did not receive the capacity error: %+v", overflowMessages)
	}

	s.detachPeer(first, "left lobby")
	_, replacementMessages := join("replacement")
	if len(replacementMessages) == 0 || replacementMessages[0].Type != "lobby-wait" {
		t.Fatalf("released lobby slot was not reusable: %+v", replacementMessages)
	}
}

func TestJoinAttemptsAreRateLimitedPerConnection(t *testing.T) {
	s := &server{limits: relayLimits{JoinRatePerMinute: 2, MaxConcurrentJoins: 1}}
	p := &peer{id: "rate-limited"}
	messages := make([]signalMsg, 0, 3)
	p.writeHook = func(value any) {
		if msg, ok := value.(signalMsg); ok {
			messages = append(messages, msg)
		}
	}
	for i := 0; i < 3; i++ {
		s.handleJoin(context.Background(), p, signalMsg{Type: "join", Room: "closed-room"})
	}
	if len(messages) != 3 || messages[2].Code != "join-rate-limit" {
		t.Fatalf("join rate limit messages = %+v", messages)
	}
}

func TestBroadcastStateChangesDropNoOpsAndRateLimitAlternatingFlood(t *testing.T) {
	r := securityTestRoom()
	s := &server{}
	actor := &peer{id: "actor", room: r, role: roleGuest}
	observer := &peer{id: "observer", room: r, role: roleGuest}
	r.peers[actor.id] = actor
	r.peers[observer.id] = observer

	handBroadcasts := 0
	observer.writeHook = func(value any) {
		if msg, ok := value.(signalMsg); ok && msg.Type == "hand-state" {
			handBroadcasts++
		}
	}
	for i := 0; i < 100; i++ {
		s.handleHandRaised(context.Background(), actor, signalMsg{}, false)
	}
	if handBroadcasts != 0 {
		t.Fatalf("no-op hand state broadcasts = %d, want 0", handBroadcasts)
	}

	for i := 0; i < 200; i++ {
		s.handleHandRaised(context.Background(), actor, signalMsg{}, i%2 == 0)
	}
	if handBroadcasts == 0 || handBroadcasts > int(defaultStateChangeBurst)+1 {
		t.Fatalf("flood hand state broadcasts = %d, want 1..%d", handBroadcasts, int(defaultStateChangeBurst)+1)
	}
}

func TestMediaStateDropsNoOpsAndRateLimitsAlternatingFlood(t *testing.T) {
	r := securityTestRoom()
	s := &server{}
	actor := &peer{id: "actor", room: r, role: roleGuest}
	observer := &peer{id: "observer", room: r, role: roleGuest}
	r.peers[actor.id] = actor
	r.peers[observer.id] = observer

	mediaBroadcasts := 0
	observer.writeHook = func(value any) {
		if msg, ok := value.(signalMsg); ok && msg.Type == "peer-media-state" {
			mediaBroadcasts++
		}
	}
	unchanged := false
	for i := 0; i < 100; i++ {
		s.handleMediaState(context.Background(), actor, signalMsg{AudioEnabled: &unchanged})
	}
	if mediaBroadcasts != 0 {
		t.Fatalf("no-op media state broadcasts = %d, want 0", mediaBroadcasts)
	}

	for i := 0; i < 200; i++ {
		enabled := i%2 == 0
		s.handleMediaState(context.Background(), actor, signalMsg{AudioEnabled: &enabled})
	}
	if mediaBroadcasts == 0 || mediaBroadcasts > int(defaultStateChangeBurst)+1 {
		t.Fatalf("flood media state broadcasts = %d, want 1..%d", mediaBroadcasts, int(defaultStateChangeBurst)+1)
	}
}

func TestQuoteSQLIdentifierRejectsNUL(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("identifier containing NUL was accepted")
		}
	}()
	_ = quoteSQLIdentifier("rooms\x00injected")
}

func TestPingReportRequiresAdmissionAndChangedNonnegativeRTT(t *testing.T) {
	r := securityTestRoom()
	s := &server{}
	actor := &peer{id: "actor", room: r, role: roleGuest, pending: true}
	observer := &peer{id: "observer", room: r, role: roleGuest}
	r.peers[actor.id], r.peers[observer.id] = actor, observer
	var received []signalMsg
	observer.writeHook = func(value any) { received = append(received, value.(signalMsg)) }
	s.handleSignal(context.Background(), &peer{id: "pre-join"}, signalMsg{Type: "pingReport", RTT: 10})
	s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 10})
	actor.pending = false
	s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: -1})
	s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 0})
	if len(received) != 0 || actor.pingMs.Load() != 0 {
		t.Fatal("invalid, pending or unchanged ping report changed room state")
	}
	for i := 0; i < 200; i++ {
		s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 42})
	}
	if len(received) != 1 || received[0].Type != "peer-ping" || received[0].RTT != 42 {
		t.Fatalf("identical ping reports produced %d updates: %+v", len(received), received)
	}
}

func TestPingReportAlternatingFloodSharesParticipantStateBudget(t *testing.T) {
	r := securityTestRoom()
	s := &server{}
	actor := &peer{id: "actor", room: r, role: roleGuest}
	observer := &peer{id: "observer", room: r, role: roleGuest}
	r.peers[actor.id], r.peers[observer.id] = actor, observer
	// Hold replenishment in the future so the burst assertion does not depend
	// on the speed of the test host or the race detector.
	actor.stateRateLast = time.Now().Add(time.Hour)
	actor.stateRateTokens = defaultStateChangeBurst
	broadcasts, pingEchoes := 0, 0
	observer.writeHook = func(value any) { broadcasts++ }
	actor.writeHook = func(value any) {
		if value.(signalMsg).Type == "peer-ping" {
			pingEchoes++
		}
	}
	for i := 0; i < 200; i++ {
		s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: int64(i%2 + 1)})
		s.handleSignal(context.Background(), actor, signalMsg{Type: "set-hand-raised", HandRaised: !actor.handRaised.Load()})
		enabled := !actor.audioEnabled.Load()
		s.handleSignal(context.Background(), actor, signalMsg{Type: "media-state", AudioEnabled: &enabled})
	}
	if broadcasts != int(defaultStateChangeBurst) || pingEchoes != 0 {
		t.Fatalf("mixed state flood: broadcasts=%d ping echoes=%d", broadcasts, pingEchoes)
	}
	previous := actor.pingMs.Load()
	s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 999})
	if actor.pingMs.Load() != previous || broadcasts != int(defaultStateChangeBurst) {
		t.Fatal("rate-limited ping report changed state")
	}
	actor.stateRateMu.Lock()
	actor.stateRateLast = time.Now().Add(-time.Second)
	actor.stateRateMu.Unlock()
	s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 999})
	if actor.pingMs.Load() != 999 || broadcasts != int(defaultStateChangeBurst)+1 {
		t.Fatal("ping reporting did not recover after the rate limit")
	}
}

func TestConcurrentDuplicatePingReportsBroadcastOnce(t *testing.T) {
	r := securityTestRoom()
	s := &server{}
	actor := &peer{id: "actor", room: r, role: roleGuest}
	observer := &peer{id: "observer", room: r, role: roleGuest}
	r.peers[actor.id], r.peers[observer.id] = actor, observer
	var broadcasts atomic.Int64
	observer.writeHook = func(any) { broadcasts.Add(1) }
	var workers sync.WaitGroup
	for i := 0; i < 64; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.handleSignal(context.Background(), actor, signalMsg{Type: "pingReport", RTT: 42})
		}()
	}
	workers.Wait()
	if broadcasts.Load() != 1 {
		t.Fatalf("concurrent duplicate ping reports produced %d broadcasts", broadcasts.Load())
	}
}

func TestWebSocketDuplicatePingReportsDoNotAmplify(t *testing.T) {
	relay := newMediaE2ERelay(t)
	relay.settings = map[string]roomSettings{mediaE2ERoom: {AdmitWithoutApproval: true}}
	httpServer := httptest.NewServer(http.HandlerFunc(relay.wsHandler))
	defer httpServer.Close()
	assertDuplicatePingReportsBounded(t, "ws"+strings.TrimPrefix(httpServer.URL, "http"), mediaE2ERoom, mediaE2ERoomInstance, serverVersion)
}

func assertDuplicatePingReportsBounded(t *testing.T, wsURL, roomName, roomInstance, version string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connections := make([]*websocket.Conn, 2)
	for i := range connections {
		conn, _, err := websocket.Dial(ctx, wsURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		connections[i] = conn
		defer conn.CloseNow()
		if err := wsjson.Write(ctx, conn, signalMsg{Type: "join", Room: roomName, RoomInstance: roomInstance, ClientVersion: version}); err != nil {
			t.Fatal(err)
		}
		var joined signalMsg
		if err := wsjson.Read(ctx, conn, &joined); err != nil || joined.Type != "join" || joined.Role != roleGuest {
			t.Fatalf("guest join: %+v, %v", joined, err)
		}
	}
	for i := 0; i < 200; i++ {
		if err := wsjson.Write(ctx, connections[0], signalMsg{Type: "pingReport", RTT: 42}); err != nil {
			t.Fatal(err)
		}
	}
	// A pong from the sender confirms all its reports were processed. A later
	// pong on the observer bounds its queue without relying on a sleep.
	counts := make([]int, 2)
	for i, conn := range connections {
		if err := wsjson.Write(ctx, conn, signalMsg{Type: "ping", Seq: 1}); err != nil {
			t.Fatal(err)
		}
		for {
			var msg signalMsg
			if err := wsjson.Read(ctx, conn, &msg); err != nil {
				t.Fatal(err)
			}
			if msg.Type == "pong" {
				break
			}
			if msg.Type == "peer-ping" {
				counts[i]++
			}
		}
	}
	if counts[0] != 0 || counts[1] != 1 {
		t.Fatalf("200 identical reports: sender echoes=%d observer updates=%d", counts[0], counts[1])
	}
}

func lobbyIncrementalEgress(t *testing.T, count int) int64 {
	t.Helper()
	r := securityTestRoom()
	r.moderatorKey = "moderator-key"
	s := &server{
		limits: relayLimits{
			MaxActivePeers:       10,
			MaxPendingLobbyPeers: count + 10,
			JoinRatePerMinute:    10,
			MaxConcurrentJoins:   64,
		},
		rooms:         map[string]*room{r.name: r},
		openRooms:     map[string]string{r.name: r.moderatorKey},
		roomInstances: map[string]string{r.name: r.instance},
		settings:      make(map[string]roomSettings),
	}
	moderator := &peer{id: "moderator", room: r, role: roleModerator}
	r.peers[moderator.id] = moderator

	var bytesWritten int64
	var messages int
	moderator.writeHook = func(value any) {
		msg, ok := value.(signalMsg)
		if !ok {
			t.Fatalf("unexpected lobby message type %T", value)
		}
		if len(msg.Pending) != 0 {
			t.Fatalf("incremental event %s contained a full pending snapshot", msg.Type)
		}
		encoded, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal lobby event: %v", err)
		}
		bytesWritten += int64(len(encoded))
		messages++
	}

	joined := make([]*peer, 0, count)
	for i := 0; i < count; i++ {
		pendingPeer := &peer{
			id:   fmt.Sprintf("pending-%04d", i),
			role: roleGuest,
		}
		joined = append(joined, pendingPeer)
		s.handleJoin(context.Background(), pendingPeer, signalMsg{
			Type:          "join",
			Room:          r.name,
			RoomInstance:  r.instance,
			Username:      fmt.Sprintf("participant-%04d", i),
			ClientVersion: serverVersion,
		})
	}
	for _, pendingPeer := range joined {
		s.detachPeer(pendingPeer, "left lobby")
	}

	if messages != count*2 {
		t.Fatalf("lobby messages = %d, want %d", messages, count*2)
	}
	return bytesWritten
}

func TestLobbyIncrementalEgressScalesLinearlyAtLargeSizes(t *testing.T) {
	bytes500 := lobbyIncrementalEgress(t, 500)
	bytes1200 := lobbyIncrementalEgress(t, 1200)

	perEvent500 := float64(bytes500) / 1000
	perEvent1200 := float64(bytes1200) / 2400
	if perEvent1200 > perEvent500*1.15 {
		t.Fatalf("lobby egress per event grew with lobby size: 500=%0.2f bytes, 1200=%0.2f bytes", perEvent500, perEvent1200)
	}
	if float64(bytes1200)/float64(bytes500) > 2.8 {
		t.Fatalf("lobby egress is not approximately linear: 500=%d bytes, 1200=%d bytes", bytes500, bytes1200)
	}
}

func TestExplicitLobbySnapshotsAreCoalesced(t *testing.T) {
	s := &server{}
	r := securityTestRoom()
	moderator := &peer{id: "moderator", room: r, role: roleModerator}
	r.peers[moderator.id] = moderator
	writes := 0
	moderator.writeHook = func(value any) {
		if msg, ok := value.(signalMsg); ok && msg.Type == "lobby-state" {
			writes++
		}
	}
	for i := 0; i < 20; i++ {
		s.scheduleLobbySnapshot(moderator)
	}
	if writes != 1 {
		t.Fatalf("immediate full lobby snapshots = %d, want 1", writes)
	}
	moderator.stopLobbySnapshotTimer()
}
