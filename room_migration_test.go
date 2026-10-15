package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func migrationFixture(t *testing.T) (*sql.DB, string, *moderatorKeyCipher) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rooms.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keys, err := newModeratorKeyCipher(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return db, path, keys
}

func TestStartupMigratesLegacyRoomsAndPreservesKeysAfterRestart(t *testing.T) {
	for _, mode := range []string{"DELETE", "WAL"} {
		t.Run(mode, func(t *testing.T) {
			db, path, keys := migrationFixture(t)
			if _, err := db.Exec("PRAGMA journal_mode=" + mode); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE open_rooms(room_name TEXT PRIMARY KEY, moderator_key TEXT NOT NULL)"); err != nil {
				t.Fatal(err)
			}
			for i := range 30 {
				if _, err := db.Exec("INSERT INTO open_rooms VALUES (?, ?)", fmt.Sprintf("room-%02d", i), fmt.Sprintf("legacy-secret-%02d-%s", i, strings.Repeat("x", 64))); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			start := func() *server {
				return newServer(nil, true, true, nil, "", path, "open_rooms", "room_name", "moderator_key", "test-admin", "test-relay", 32768, 60999, defaultRelayLimits(), keys)
			}
			first := start()
			if len(first.openRooms) != 30 {
				t.Fatalf("loaded %d rooms, want 30", len(first.openRooms))
			}
			for room, key := range first.openRooms {
				if key != "legacy-secret-"+strings.TrimPrefix(room, "room-")+"-"+strings.Repeat("x", 64) {
					t.Fatalf("moderator credential changed for %s", room)
				}
				if !isValidRoomInstance(first.roomInstances[room]) {
					t.Fatalf("missing instance for %s", room)
				}
				var stored string
				if err := first.db.QueryRow("SELECT moderator_key FROM open_rooms WHERE room_name = ?", room).Scan(&stored); err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(stored, encryptedModeratorKeyPrefix) {
					t.Fatalf("unencrypted key for %s", room)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte("legacy-secret-")) {
				t.Fatal("legacy plaintext survived in SQLite pages")
			}
			if wal, err := os.ReadFile(path + "-wal"); err == nil && bytes.Contains(wal, []byte("legacy-secret-")) {
				t.Fatal("legacy plaintext survived in SQLite WAL")
			}
			_ = first.db.Close()
			second := start()
			defer second.db.Close()
			for room, key := range first.openRooms {
				if second.openRooms[room] != key || second.roomInstances[room] != first.roomInstances[room] {
					t.Fatalf("restart changed credential or instance for %s", room)
				}
			}
		})
	}
}

func TestRoomMigrationPreservesExistingEncryptedRoomsAndSettings(t *testing.T) {
	db, _, keys := migrationFixture(t)
	if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
		t.Fatal(err)
	}
	encrypted, err := keys.seal("existing", "existing-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO open_rooms VALUES (?, ?, ?, ?, ?, ?)", "existing", encrypted, 1, 1, "0.3.3", "existing-instance"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO open_rooms(room_name, moderator_key) VALUES ('empty-key', '')"); err != nil {
		t.Fatal(err)
	}
	records, err := loadAndMigrateRooms(db, "open_rooms", "room_name", "moderator_key", keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].moderatorKey == "" {
		t.Fatal("empty legacy key was not generated")
	}
	got := records[1]
	if got.moderatorKey != "existing-key" || got.instance != "existing-instance" || got.requiredVersion != "0.3.3" || !got.settings.MuteAllByDefault || !got.settings.AdmitWithoutApproval {
		t.Fatal("existing room settings, version, instance or key changed")
	}
	var stored string
	if err := db.QueryRow("SELECT moderator_key FROM open_rooms WHERE room_name = 'existing'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != encrypted {
		t.Fatal("existing ciphertext was unnecessarily rewritten")
	}
}

func TestRoomMigrationRollsBackAllRowsOnWriteFailure(t *testing.T) {
	db, _, keys := migrationFixture(t)
	if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		if _, err := db.Exec("INSERT INTO open_rooms(room_name, moderator_key) VALUES (?, ?)", name, "legacy-"+name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_second BEFORE UPDATE OF moderator_key ON open_rooms WHEN OLD.room_name = 'b' BEGIN SELECT RAISE(ABORT, 'test write failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndMigrateRooms(db, "open_rooms", "room_name", "moderator_key", keys); err == nil {
		t.Fatal("migration accepted a failed write")
	}
	for _, name := range []string{"a", "b"} {
		var key, instance string
		if err := db.QueryRow("SELECT moderator_key, room_instance FROM open_rooms WHERE room_name = ?", name).Scan(&key, &instance); err != nil {
			t.Fatal(err)
		}
		if key != "legacy-"+name || instance != "" {
			t.Fatalf("partial migration committed for %s", name)
		}
	}
}

func TestRoomMigrationRejectsCorruptEncryptedKeyWithoutPartialWrites(t *testing.T) {
	db, _, keys := migrationFixture(t)
	if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO open_rooms(room_name, moderator_key) VALUES ('a', 'legacy-a'), ('b', 'enc:v1:broken')"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndMigrateRooms(db, "open_rooms", "room_name", "moderator_key", keys); err == nil {
		t.Fatal("migration accepted a corrupt ciphertext")
	}
	var key string
	if err := db.QueryRow("SELECT moderator_key FROM open_rooms WHERE room_name = 'a'").Scan(&key); err != nil || key != "legacy-a" {
		t.Fatalf("migration was partially committed: %v", err)
	}
}
