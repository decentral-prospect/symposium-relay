package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		"INSERT INTO open_rooms(room_name, moderator_key, room_instance) VALUES(?, ?, ?)",
		roomName,
		moderatorKey,
		"test-room-instance",
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

	moderatorKeys, err := newModeratorKeyCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("create moderator key cipher: %v", err)
	}

	return &server{
		db:            db,
		adminToken:    "test-admin-token",
		dbTable:       "open_rooms",
		dbRoomColumn:  "room_name",
		dbKeyColumn:   "moderator_key",
		moderatorKeys: moderatorKeys,
		rooms:         map[string]*room{roomName: liveRoom},
		openRooms:     map[string]string{roomName: moderatorKey},
		roomInstances: map[string]string{roomName: "test-room-instance"},
		roomVersions:  map[string]string{roomName: serverVersion},
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
	if storedKey == newKey || !strings.HasPrefix(storedKey, encryptedModeratorKeyPrefix) {
		t.Fatalf("stored moderator key is not encrypted: %q", storedKey)
	}
	decryptedKey, err := s.moderatorKeys.open(roomName, storedKey)
	if err != nil {
		t.Fatalf("decrypt stored key: %v", err)
	}
	if decryptedKey != newKey {
		t.Fatalf("decrypted stored key = %q, want %q", decryptedKey, newKey)
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
	if response.RequiredVersion != serverVersion {
		t.Fatalf("response required version = %q, want %q", response.RequiredVersion, serverVersion)
	}
}

func TestEveryAdminHandlerRejectsRequestsWithoutToken(t *testing.T) {
	s, _ := newModeratorRotationTestServer(t, "protected-room", "protected-key")
	tests := []struct {
		name    string
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{"version", http.MethodGet, "/admin/version", s.adminVersionHandler},
		{"open-room", http.MethodPost, "/admin/open-room?name=another-room", s.adminOpenRoomHandler},
		{"close-room", http.MethodPost, "/admin/close-room?name=protected-room", s.adminCloseRoomHandler},
		{"open-rooms", http.MethodGet, "/admin/open-rooms", s.adminOpenRoomsHandler},
		{"rotate-moderator-key", http.MethodPost, "/admin/rotate-moderator-key?name=protected-room", s.adminRotateModeratorKeyHandler},
		{"room-settings", http.MethodPost, "/admin/room-settings?name=protected-room", s.adminRoomSettingsHandler},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, nil)
			test.handler(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestRoomSettingsPersistAndApplyToLiveRoom(t *testing.T) {
	const roomName = "settings-room"
	s, liveRoom := newModeratorRotationTestServer(t, roomName, "settings-key")
	want := roomSettings{MuteAllByDefault: true, AdmitWithoutApproval: true}

	if err := s.setRoomSettings(roomName, want); err != nil {
		t.Fatalf("set room settings: %v", err)
	}
	if got := s.roomSettings(roomName); got != want {
		t.Fatalf("in-memory settings = %+v, want %+v", got, want)
	}
	liveRoom.mu.RLock()
	gotMuteAll := liveRoom.muteAll
	gotAdmission := liveRoom.admitWithoutApproval
	liveRoom.mu.RUnlock()
	if !gotMuteAll || !gotAdmission || !liveRoom.admitsWithoutApproval() {
		t.Fatalf("live room settings were not applied: mute=%t admission=%t", gotMuteAll, gotAdmission)
	}

	var storedMuteAll, storedAdmission int
	if err := s.db.QueryRow(
		"SELECT mute_all_by_default, admit_without_approval FROM open_rooms WHERE room_name = ?",
		roomName,
	).Scan(&storedMuteAll, &storedAdmission); err != nil {
		t.Fatalf("read stored settings: %v", err)
	}
	if storedMuteAll != 1 || storedAdmission != 1 {
		t.Fatalf("stored settings = %d/%d, want 1/1", storedMuteAll, storedAdmission)
	}
}

func TestOpenRoomWithSettingsReturnsSettingsInListing(t *testing.T) {
	s, _ := newModeratorRotationTestServer(t, "existing-room", "existing-key")
	want := roomSettings{MuteAllByDefault: true, AdmitWithoutApproval: true}
	if _, err := s.openRoomWithSettings("new-room", &want); err != nil {
		t.Fatalf("open room with settings: %v", err)
	}

	for _, opened := range s.listOpenRooms() {
		if opened.Room == "new-room" {
			if !opened.MuteAllByDefault || !opened.AdmitWithoutApproval {
				t.Fatalf("listed settings = %+v", opened)
			}
			if opened.RequiredVersion != serverVersion {
				t.Fatalf("listed required version = %q, want %q", opened.RequiredVersion, serverVersion)
			}
			return
		}
	}
	t.Fatal("new room was not returned by the listing")
}

func TestOpenRoomWithoutSettingsKeepsExistingValues(t *testing.T) {
	const roomName = "existing-settings"
	s, _ := newModeratorRotationTestServer(t, roomName, "existing-key")
	want := roomSettings{MuteAllByDefault: true, AdmitWithoutApproval: true}
	if err := s.setRoomSettings(roomName, want); err != nil {
		t.Fatalf("set room settings: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/admin/open-room?name="+roomName, nil)
	request.Header.Set(adminTokenHeader, s.adminToken)
	response := httptest.NewRecorder()
	s.adminOpenRoomHandler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := s.roomSettings(roomName); got != want {
		t.Fatalf("settings = %+v, want %+v", got, want)
	}
	var storedModeratorKey string
	if err := s.db.QueryRow(
		"SELECT moderator_key FROM open_rooms WHERE room_name = ?",
		roomName,
	).Scan(&storedModeratorKey); err != nil {
		t.Fatalf("read encrypted moderator key: %v", err)
	}
	if !strings.HasPrefix(storedModeratorKey, encryptedModeratorKeyPrefix) || strings.Contains(storedModeratorKey, "existing-key") {
		t.Fatalf("moderator key remains plaintext in SQLite: %q", storedModeratorKey)
	}
}

func TestRecreatedRoomGetsNewInstanceAndRejectsOldInvitation(t *testing.T) {
	s, _ := newModeratorRotationTestServer(t, "recreated-room", "moderator-key")
	firstInstance, ok := s.roomInstance("recreated-room")
	if !ok {
		t.Fatal("initial room instance is missing")
	}
	if err := s.closeRoom("recreated-room"); err != nil {
		t.Fatalf("close room: %v", err)
	}
	if _, err := s.openRoom("recreated-room"); err != nil {
		t.Fatalf("reopen room: %v", err)
	}
	secondInstance, ok := s.roomInstance("recreated-room")
	if !ok || secondInstance == firstInstance {
		t.Fatalf("recreated room instance = %q, first = %q", secondInstance, firstInstance)
	}

	var response signalMsg
	p := &peer{id: "stale-invitation", writeHook: func(value any) { response = value.(signalMsg) }}
	s.handleJoin(context.Background(), p, signalMsg{
		Type:          "join",
		Room:          "recreated-room",
		RoomInstance:  firstInstance,
		ClientVersion: serverVersion,
	})
	if response.Code != "invitation-invalid" {
		t.Fatalf("stale invitation response = %+v", response)
	}
}

func TestAdminRoomSettingsHandlerRequiresAdminAndUpdatesRoom(t *testing.T) {
	const roomName = "handler-settings"
	s, _ := newModeratorRotationTestServer(t, roomName, "handler-key")
	path := "/admin/room-settings?name=" + roomName +
		"&muteAllByDefault=true&admitWithoutApproval=true"

	unauthorized := httptest.NewRecorder()
	s.adminRoomSettingsHandler(unauthorized, httptest.NewRequest(http.MethodPost, path, nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set(adminTokenHeader, s.adminToken)
	response := httptest.NewRecorder()
	s.adminRoomSettingsHandler(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body openRoomResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Room != roomName || !body.MuteAllByDefault || !body.AdmitWithoutApproval {
		t.Fatalf("response=%+v", body)
	}
}

func TestEnsureRoomSchemaMigratesExistingTable(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE open_rooms(room_name TEXT PRIMARY KEY, moderator_key TEXT NOT NULL)"); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := db.Exec("INSERT INTO open_rooms(room_name, moderator_key) VALUES('legacy', 'key')"); err != nil {
		t.Fatalf("insert legacy room: %v", err)
	}

	if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
		t.Fatalf("migrate room schema: %v", err)
	}
	var muteAll, admission int
	var requiredVersion string
	if err := db.QueryRow(
		"SELECT mute_all_by_default, admit_without_approval, required_version FROM open_rooms WHERE room_name = 'legacy'",
	).Scan(&muteAll, &admission, &requiredVersion); err != nil {
		t.Fatalf("read migrated defaults: %v", err)
	}
	if muteAll != 0 || admission != 0 {
		t.Fatalf("migrated defaults = %d/%d, want 0/0", muteAll, admission)
	}
	if requiredVersion != serverVersion {
		t.Fatalf("migrated required version = %q, want %q", requiredVersion, serverVersion)
	}
}

func TestJoinRejectsMissingOlderNewerOrNonCanonicalClientVersion(t *testing.T) {
	s := &server{
		openRooms:     map[string]string{"versioned-room": "moderator-key"},
		roomInstances: map[string]string{"versioned-room": "test-room-instance"},
		roomVersions:  map[string]string{"versioned-room": "0.3.4"},
	}
	tests := map[string]string{
		"missing":       "",
		"older":         "0.3.3",
		"newer":         "0.3.5",
		"non-canonical": "v0.3.4",
	}

	for name, clientVersion := range tests {
		t.Run(name, func(t *testing.T) {
			var response signalMsg
			p := &peer{
				id: "incompatible-peer-" + name,
				writeHook: func(value any) {
					response = value.(signalMsg)
				},
			}

			s.handleJoin(context.Background(), p, signalMsg{
				Type:          "join",
				Room:          "versioned-room",
				RoomInstance:  "test-room-instance",
				ClientVersion: clientVersion,
			})

			if response.Code != "client-version-mismatch" {
				t.Fatalf("error code = %q, want client-version-mismatch", response.Code)
			}
			if response.RequiredVersion != "0.3.4" {
				t.Fatalf("required version = %q, want 0.3.4", response.RequiredVersion)
			}
			if !p.closed.Load() {
				t.Fatal("incompatible peer connection was not closed")
			}
			if p.getRoom() != nil {
				t.Fatal("incompatible peer joined the room")
			}
		})
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
