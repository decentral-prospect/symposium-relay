package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func newModeratorRotationTestServer(t *testing.T, roomName string, moderatorKey string) (*server, *room) {
	t.Helper()

	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "rooms.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
		t.Fatalf("create room schema: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO open_rooms(room_name, moderator_key) VALUES(?, ?)",
		roomName,
		moderatorKey,
	); err != nil {
		t.Fatalf("insert room: %v", err)
	}

	liveRoom := &room{
		name:         roomName,
		moderatorKey: moderatorKey,
		peers:        make(map[string]*peer),
		pending:      make(map[string]*peer),
		pubs:         make(map[string]*publication),
		muteAllow:    make(map[string]bool),
		muted:        make(map[string]bool),
	}

	return &server{
		db:            db,
		adminToken:    "test-admin-token",
		dbTable:       "open_rooms",
		dbRoomColumn:  "room_name",
		dbKeyColumn:   "moderator_key",
		rooms:         map[string]*room{roomName: liveRoom},
		openRooms:     map[string]string{roomName: moderatorKey},
		publicBaseURL: "https://relay.example",
	}, liveRoom
}

func TestRotateModeratorKeyRevokesOldKeyAndActiveModerators(t *testing.T) {
	const roomName = "security-room"
	const oldKey = "old-moderator-key"
	s, liveRoom := newModeratorRotationTestServer(t, roomName, oldKey)

	moderator := &peer{
		id:             "moderator-peer",
		role:           roleModerator,
		room:           liveRoom,
		subs:           make(map[string]*subscription),
		discoTimers:    make(map[string]*time.Timer),
		reconnectToken: "moderator-reconnect",
	}
	guest := &peer{
		id:          "guest-peer",
		role:        roleGuest,
		room:        liveRoom,
		subs:        make(map[string]*subscription),
		discoTimers: make(map[string]*time.Timer),
	}
	liveRoom.peers[moderator.id] = moderator
	liveRoom.peers[guest.id] = guest

	newKey, err := s.rotateModeratorKey(roomName)
	if err != nil {
		t.Fatalf("rotate moderator key: %v", err)
	}
	if newKey == "" || newKey == oldKey {
		t.Fatalf("expected a new non-empty key, got %q", newKey)
	}
	if isModeratorKeyValid(oldKey, newKey) {
		t.Fatal("old moderator key is still valid")
	}
	if !isModeratorKeyValid(newKey, newKey) {
		t.Fatal("new moderator key is not valid")
	}
	if !moderator.closed.Load() {
		t.Fatal("active moderator was not disconnected")
	}
	if guest.closed.Load() {
		t.Fatal("guest was disconnected during moderator key rotation")
	}
	if got := liveRoom.moderatorKeyValue(); got != newKey {
		t.Fatalf("live room key = %q, want %q", got, newKey)
	}
	if got, ok := s.roomModeratorKey(roomName); !ok || got != newKey {
		t.Fatalf("open room key = %q, %v; want %q, true", got, ok, newKey)
	}

	var storedKey string
	if err := s.db.QueryRow(
		"SELECT moderator_key FROM open_rooms WHERE room_name = ?",
		roomName,
	).Scan(&storedKey); err != nil {
		t.Fatalf("read stored key: %v", err)
	}
	if storedKey != newKey {
		t.Fatalf("stored key = %q, want %q", storedKey, newKey)
	}
}

func TestAdminRotateModeratorKeyHandlerRequiresAdminAndReturnsNewKey(t *testing.T) {
	const roomName = "handler-room"
	const oldKey = "handler-old-key"
	s, _ := newModeratorRotationTestServer(t, roomName, oldKey)

	unauthorizedRequest := httptest.NewRequest(
		http.MethodPost,
		"/admin/rotate-moderator-key?name="+roomName,
		nil,
	)
	unauthorizedResponse := httptest.NewRecorder()
	s.adminRotateModeratorKeyHandler(unauthorizedResponse, unauthorizedRequest)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorizedResponse.Code, http.StatusUnauthorized)
	}

	authorizedRequest := httptest.NewRequest(
		http.MethodPost,
		"/admin/rotate-moderator-key?name="+roomName,
		nil,
	)
	authorizedRequest.Header.Set(adminTokenHeader, s.adminToken)
	authorizedResponse := httptest.NewRecorder()
	s.adminRotateModeratorKeyHandler(authorizedResponse, authorizedRequest)
	if authorizedResponse.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want %d: %s", authorizedResponse.Code, http.StatusOK, authorizedResponse.Body.String())
	}

	var response openRoomResponse
	if err := json.NewDecoder(authorizedResponse.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Room != roomName {
		t.Fatalf("response room = %q, want %q", response.Room, roomName)
	}
	if response.ModeratorKey == "" || response.ModeratorKey == oldKey {
		t.Fatalf("response moderator key was not rotated: %q", response.ModeratorKey)
	}
	if response.ModLinkData.ModeratorKey != response.ModeratorKey {
		t.Fatal("moderator link data does not contain the rotated key")
	}
}

func TestPeerCloseStatusForReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   websocket.StatusCode
	}{
		{name: "publish disconnected", reason: "publish disconnected", want: websocket.StatusTryAgainLater},
		{name: "subscribe failed", reason: "subscribe failed", want: websocket.StatusTryAgainLater},
		{name: "pc create failed", reason: "subscribe pc create failed after lobby approval", want: websocket.StatusTryAgainLater},
		{name: "room closed", reason: "room closed by admin", want: websocket.StatusNormalClosure},
		{name: "replaced reconnect", reason: "replaced by reconnect", want: websocket.StatusNormalClosure},
		{name: "client websocket closed", reason: "ws closed", want: websocket.StatusNormalClosure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerCloseStatusForReason(tt.reason); got != tt.want {
				t.Fatalf("peerCloseStatusForReason(%q) = %d, want %d", tt.reason, got, tt.want)
			}
		})
	}
}

func TestReconnectResumeStatePreservesApprovedGuestModeration(t *testing.T) {
	r := &room{
		name:      "resume-room",
		peers:     make(map[string]*peer),
		pending:   make(map[string]*peer),
		pubs:      make(map[string]*publication),
		muteAllow: make(map[string]bool),
		muted:     make(map[string]bool),
	}
	approved := &peer{
		id:          "approved-guest",
		role:        roleGuest,
		room:        r,
		subs:        make(map[string]*subscription),
		discoTimers: make(map[string]*time.Timer),
	}
	approved.handRaised.Store(true)
	r.peers[approved.id] = approved
	r.muted[approved.id] = true
	r.muteAllow[approved.id] = true

	state := reconnectResumeStateForPeers(r, []*peer{approved})
	if !state.approvedGuest || !state.explicitlyMuted || !state.muteAllowed || !state.handRaised {
		t.Fatalf("approved guest resume state was not preserved: %+v", state)
	}

	pending := &peer{
		id:          "pending-guest",
		role:        roleGuest,
		room:        r,
		pending:     true,
		subs:        make(map[string]*subscription),
		discoTimers: make(map[string]*time.Timer),
	}
	r.pending[pending.id] = pending
	if got := reconnectResumeStateForPeers(r, []*peer{pending}); got.approvedGuest {
		t.Fatalf("pending guest unexpectedly resumed as approved: %+v", got)
	}
}
