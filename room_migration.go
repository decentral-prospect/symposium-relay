package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type persistedRoom struct {
	name            string
	moderatorKey    string
	instance        string
	requiredVersion string
	settings        roomSettings
}

// Keep schema changes, encryption and instance backfill on one connection and
// in one transaction. Close the SELECT before updating: a separate connection
// cannot commit while that cursor holds SQLite's read lock.
func loadAndMigrateRooms(db *sql.DB, table, roomColumn, keyColumn string, keys *moderatorKeyCipher) ([]persistedRoom, error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Keep connection-local journal settings through migration and compaction.
	// PERSIST journals must not retain the old pages backed up by VACUUM.
	if _, err := conn.ExecContext(ctx, "PRAGMA journal_size_limit = 0"); err != nil {
		return nil, fmt.Errorf("limit migration journal: %w", err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Schema updates can relocate a legacy plaintext row too. Erase replaced
	// cells from the beginning of the migration, not just at the encryption step.
	if _, err := tx.Exec("PRAGMA secure_delete = ON"); err != nil {
		return nil, err
	}
	if err := ensureRoomSchema(tx, table, roomColumn, keyColumn); err != nil {
		return nil, fmt.Errorf("initialize room schema: %w", err)
	}
	rows, err := tx.Query(fmt.Sprintf(
		"SELECT %s, %s, room_instance, required_version, mute_all_by_default, admit_without_approval FROM %s ORDER BY %s",
		quoteSQLIdentifier(roomColumn), quoteSQLIdentifier(keyColumn), quoteSQLIdentifier(table), quoteSQLIdentifier(roomColumn),
	))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []persistedRoom
	for rows.Next() {
		var record persistedRoom
		var muteAll, admission int
		if err := rows.Scan(&record.name, &record.moderatorKey, &record.instance, &record.requiredVersion, &muteAll, &admission); err != nil {
			return nil, fmt.Errorf("read room: %w", err)
		}
		record.settings = roomSettings{MuteAllByDefault: muteAll != 0, AdmitWithoutApproval: admission != 0}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	loaded := make([]persistedRoom, 0, len(records))
	for _, record := range records {
		storedName := record.name
		record.name = strings.TrimSpace(record.name)
		if record.name == "" {
			continue
		}
		record.requiredVersion, err = canonicalRequiredVersion(record.requiredVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid required version for room %q: %w", record.name, err)
		}
		storedKey := strings.TrimSpace(record.moderatorKey)
		migrateKey := !strings.HasPrefix(storedKey, encryptedModeratorKeyPrefix)
		if migrateKey {
			record.moderatorKey = storedKey
			if record.moderatorKey == "" {
				record.moderatorKey = mustGenerateModeratorKey()
			}
			storedKey, err = keys.seal(record.name, record.moderatorKey)
		} else {
			record.moderatorKey, err = keys.open(record.name, storedKey)
		}
		if err != nil {
			return nil, fmt.Errorf("migrate moderator key for room %q: %w", record.name, err)
		}
		record.instance = strings.TrimSpace(record.instance)
		migrateInstance := !isValidRoomInstance(record.instance)
		if migrateInstance {
			record.instance = mustGenerateRoomInstance()
		}
		if migrateKey || migrateInstance {
			_, err = tx.Exec(fmt.Sprintf("UPDATE %s SET %s = ?, room_instance = ? WHERE %s = ?",
				quoteSQLIdentifier(table), quoteSQLIdentifier(keyColumn), quoteSQLIdentifier(roomColumn)),
				storedKey, record.instance, storedName)
			if err != nil {
				return nil, fmt.Errorf("migrate room %q: %w", record.name, err)
			}
		}
		loaded = append(loaded, record)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit room migration: %w", err)
	}
	// secure_delete cannot erase historical copies already in free pages or
	// freeblocks. Rebuild from live encrypted rows before accepting clients.
	// Run even when no live row needed migration: older releases, or a crash
	// after Commit, can leave encrypted rows alongside historical plaintext.
	if _, err := conn.ExecContext(ctx, "VACUUM"); err != nil {
		return nil, fmt.Errorf("purge historical room keys: %w", err)
	}
	// VACUUM in WAL mode does not rewrite the main file immediately. Flush the
	// compacted pages and truncate all old WAL frames; a busy checkpoint is a
	// startup failure, so the next attempt repeats the complete cleanup.
	var busy, frames, checkpointed int
	if err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &frames, &checkpointed); err != nil {
		return nil, fmt.Errorf("checkpoint migrated rooms: %w", err)
	}
	if busy != 0 {
		return nil, fmt.Errorf("checkpoint migrated rooms: database is busy")
	}
	return loaded, nil
}
