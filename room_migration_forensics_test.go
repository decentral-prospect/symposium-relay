package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

const retiredRoomKeyPrefix = "retired-moderator-secret-"

// Removing surrounding rows can relocate the surviving row and leave a copy
// of its still-active credential in a freelist page. A fresh one-row database
// cannot exercise this legacy history, even when its live value is encrypted.
func createLegacyRoomHistory(t *testing.T, db *sql.DB, mode, room, key string) {
	t.Helper()
	for _, query := range []string{
		"PRAGMA journal_mode=" + mode,
		"PRAGMA secure_delete=OFF",
		"CREATE TABLE open_rooms(room_name TEXT PRIMARY KEY, moderator_key TEXT NOT NULL)",
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range 2000 {
		name := fmt.Sprintf("room-%05d", i)
		secret := fmt.Sprintf("%s%05d-xxxxxxxxxxxxxxxx", retiredRoomKeyPrefix, i)
		if i == 1000 {
			name, secret = room, key
		}
		if _, err := tx.Exec("INSERT INTO open_rooms VALUES (?, ?)", name, secret); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM open_rooms WHERE room_name != ?", room); err != nil {
		t.Fatal(err)
	}
	var freePages int
	if err := db.QueryRow("PRAGMA freelist_count").Scan(&freePages); err != nil || freePages == 0 {
		t.Fatalf("fixture has no historical free pages: count=%d err=%v", freePages, err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
}

func assertHistoricalKeyCopies(t *testing.T, path, key string, minimum int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(data, []byte(key)); count < minimum {
		t.Fatalf("fixture has %d plaintext copies, want at least %d", count, minimum)
	}
}

func assertNoRoomKeyTraces(t *testing.T, path string, secrets ...string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-journal"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("plaintext moderator key survived in rooms.db%s", suffix)
			}
		}
	}
}

func TestRoomMigrationPurgesHistoricalKeyCopies(t *testing.T) {
	for _, mode := range []string{"DELETE", "WAL", "PERSIST", "TRUNCATE"} {
		for _, alreadyEncrypted := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/encrypted=%t", mode, alreadyEncrypted), func(t *testing.T) {
				db, path, keys := migrationFixture(t)
				const room = "room-01000"
				const key = "active-moderator-secret-for-history-regression"
				createLegacyRoomHistory(t, db, mode, room, key)
				assertHistoricalKeyCopies(t, path, key, 2)
				if alreadyEncrypted {
					// Reproduce a previous release that encrypted the live row but
					// did not purge pre-existing copies from free pages.
					if _, err := db.Exec("PRAGMA secure_delete=ON"); err != nil {
						t.Fatal(err)
					}
					if err := ensureRoomSchema(db, "open_rooms", "room_name", "moderator_key"); err != nil {
						t.Fatal(err)
					}
					ciphertext, err := keys.seal(room, key)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec("UPDATE open_rooms SET moderator_key=?, room_instance='existing-instance', mute_all_by_default=1", ciphertext); err != nil {
						t.Fatal(err)
					}
					if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
						t.Fatal(err)
					}
					assertHistoricalKeyCopies(t, path, key, 1)
				}
				var instance string
				for run := 0; run < 2; run++ {
					records, err := loadAndMigrateRooms(db, "open_rooms", "room_name", "moderator_key", keys)
					if err != nil {
						t.Fatal(err)
					}
					if len(records) != 1 || records[0].name != room || records[0].moderatorKey != key || !isValidRoomInstance(records[0].instance) {
						t.Fatal("cleanup changed the active room or moderator credential")
					}
					if (run > 0 && records[0].instance != instance) ||
						(alreadyEncrypted && (records[0].instance != "existing-instance" || !records[0].settings.MuteAllByDefault)) {
						t.Fatal("cleanup changed the room instance or settings")
					}
					instance = records[0].instance
					var stored string
					if err := db.QueryRow("SELECT moderator_key FROM open_rooms").Scan(&stored); err != nil || !strings.HasPrefix(stored, encryptedModeratorKeyPrefix) {
						t.Fatalf("live key is not encrypted: %v", err)
					}
					assertNoRoomKeyTraces(t, path, key, retiredRoomKeyPrefix)
				}
			})
		}
	}
}

func TestRoomMigrationRetriesAfterBlockedWALCleanup(t *testing.T) {
	db, path, keys := migrationFixture(t)
	db.SetMaxOpenConns(1)
	const room = "room-01000"
	const key = "active-moderator-secret-for-interrupted-cleanup"
	createLegacyRoomHistory(t, db, "WAL", room, key)
	if _, err := db.Exec("PRAGMA busy_timeout=20"); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Rollback()
	var oldKey string
	if err := snapshot.QueryRow("SELECT moderator_key FROM open_rooms").Scan(&oldKey); err != nil || oldKey != key {
		t.Fatalf("could not pin the old WAL snapshot: %v", err)
	}
	if records, err := loadAndMigrateRooms(db, "open_rooms", "room_name", "moderator_key", keys); err == nil ||
		!strings.Contains(err.Error(), "checkpoint migrated rooms: database is busy") || records != nil {
		t.Fatalf("blocked cleanup must prevent startup: records=%d err=%v", len(records), err)
	}
	var stored, instance string
	if err := db.QueryRow("SELECT moderator_key, room_instance FROM open_rooms").Scan(&stored, &instance); err != nil ||
		!strings.HasPrefix(stored, encryptedModeratorKeyPrefix) || !isValidRoomInstance(instance) {
		t.Fatalf("fixture did not reach the committed-encryption stage: %v", err)
	}
	assertHistoricalKeyCopies(t, path, key, 1)
	if err := snapshot.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	records, err := loadAndMigrateRooms(restarted, "open_rooms", "room_name", "moderator_key", keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].moderatorKey != key || records[0].instance != instance {
		t.Fatal("restart after blocked cleanup changed the key or room instance")
	}
	assertNoRoomKeyTraces(t, path, key, retiredRoomKeyPrefix)
}
