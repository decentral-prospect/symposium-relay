package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt in with SYMPOSIUM_RELAY_BINARY=/absolute/path/to/the/release/asset.
// Exercise the executable that will be shipped, including startup and restart;
// source-level tests alone cannot catch accidentally packaging an older binary.
func TestRelayArtifactSecurity(t *testing.T) {
	binary := os.Getenv("SYMPOSIUM_RELAY_BINARY")
	if binary == "" {
		t.Skip("set SYMPOSIUM_RELAY_BINARY to check a built relay artifact")
	}
	var err error
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"DELETE", "WAL"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "rooms.db")
			const legacyKey = "artifact-test-legacy-moderator-secret"
			db, err := sql.Open("sqlite3", database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			createLegacyRoomHistory(t, db, mode, "artifact-room", legacyKey)
			assertHistoricalKeyCopies(t, database, legacyKey, 2)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(dir, "admin-token")
			if err := os.WriteFile(tokenPath, []byte("artifact-test-admin"), 0o600); err != nil {
				t.Fatal(err)
			}
			var instance string
			for run := 0; run < 2; run++ {
				func() {
					publicAddr, adminAddr := artifactTestAddress(t), artifactTestAddress(t)
					logFile, err := os.Create(filepath.Join(dir, "relay.log"))
					if err != nil {
						t.Fatal(err)
					}
					defer logFile.Close()
					cmd := exec.Command(binary,
						"--addr", publicAddr, "--admin-addr", adminAddr,
						"--rooms-db", database, "--db-table", "open_rooms",
						"--db-room-column", "room_name", "--db-key-column", "moderator_key",
						"--admin-token-file", tokenPath, "--loopback", "--allow-private-ice")
					cmd.Stdout, cmd.Stderr = logFile, logFile
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
					client := &http.Client{Timeout: time.Second}
					request := func(method, path string) (*http.Response, error) {
						req, err := http.NewRequest(method, "http://"+adminAddr+path, nil)
						if err != nil {
							return nil, err
						}
						req.Header.Set(adminTokenHeader, "artifact-test-admin")
						return client.Do(req)
					}
					ready := false
					for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
						response, err := request(http.MethodGet, "/admin/version")
						if err == nil {
							response.Body.Close()
							if response.StatusCode == http.StatusOK {
								ready = true
								break
							}
						}
						time.Sleep(50 * time.Millisecond)
					}
					if !ready {
						logs, _ := os.ReadFile(logFile.Name())
						t.Fatalf("artifact failed to start after legacy migration (run %d): %s", run+1, logs)
					}
					response, err := request(http.MethodPost, "/admin/open-room?name=artifact-room&admitWithoutApproval=true")
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					var room openRoomResponse
					if err := json.NewDecoder(response.Body).Decode(&room); err != nil {
						t.Fatal(err)
					}
					if room.ModeratorKey != legacyKey || !isValidRoomInstance(room.RoomInstance) || (run > 0 && instance != room.RoomInstance) {
						t.Fatal("artifact migration/restart lost the moderator key or room instance")
					}
					instance = room.RoomInstance
					assertNoRoomKeyTraces(t, database, legacyKey, retiredRoomKeyPrefix)
					assertDuplicatePingReportsBounded(t, "ws://"+publicAddr+"/ws", room.Room, instance, room.RequiredVersion)
				}()
				stored, err := sql.Open("sqlite3", database)
				if err != nil {
					t.Fatal(err)
				}
				var key string
				err = stored.QueryRow("SELECT moderator_key FROM open_rooms WHERE room_name = 'artifact-room'").Scan(&key)
				stored.Close()
				if err != nil || !strings.HasPrefix(key, encryptedModeratorKeyPrefix) {
					t.Fatal("artifact left the moderator key unencrypted")
				}
				assertNoRoomKeyTraces(t, database, legacyKey, retiredRoomKeyPrefix)
			}
		})
	}
}

func artifactTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}
