// Package store implements the SQLite persistence adapters.
package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	core "github.com/KLORQ/sandboxes-core"
	"github.com/KLORQ/sandboxes-core/operation"
	"github.com/KLORQ/sandboxes-core/sandbox"
	_ "modernc.org/sqlite"
)

// Store is the SQLite implementation of the daemon repositories.
type Store struct {
	db  *sql.DB
	ops *OperationStore
}

// OperationStore is the SQLite operation journal adapter.
type OperationStore struct {
	db *sql.DB
}

var _ sandbox.Store = (*Store)(nil)
var _ operation.Store = (*OperationStore)(nil)

// Open opens and migrates the SQLite database.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &Store{db: db, ops: &OperationStore{db: db}}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Operations returns the operation journal adapter.
func (s *Store) Operations() *OperationStore { return s.ops }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS sandboxes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			image TEXT NOT NULL,
			workspace TEXT NOT NULL,
			error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS operations (
			id TEXT PRIMARY KEY,
			sandbox_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			idempotency_key TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS operations_idempotency
			ON operations(idempotency_key) WHERE idempotency_key <> ''`,
		`CREATE INDEX IF NOT EXISTS operations_sandbox ON operations(sandbox_id, created_at)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// Create inserts a sandbox.
func (s *Store) Create(ctx context.Context, sb sandbox.Sandbox) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sandboxes
		(id, name, state, generation, image, workspace, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		sb.ID, sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, sb.Error,
		toUnix(sb.CreatedAt), toUnix(sb.UpdatedAt))
	return mapSQLError(err)
}

// Get returns a sandbox by ID.
func (s *Store) Get(ctx context.Context, id string) (sandbox.Sandbox, error) {
	return s.getSandbox(ctx, "id = ?", id)
}

// GetByName returns a sandbox by name.
func (s *Store) GetByName(ctx context.Context, name string) (sandbox.Sandbox, error) {
	return s.getSandbox(ctx, "name = ?", name)
}

func (s *Store) getSandbox(ctx context.Context, where string, arg any) (sandbox.Sandbox, error) {
	var sb sandbox.Sandbox
	var created, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, state, generation, image, workspace, error, created_at, updated_at
		FROM sandboxes WHERE `+where, arg).Scan(
		&sb.ID, &sb.Name, &sb.State, &sb.Generation, &sb.Image, &sb.Workspace, &sb.Error, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return sandbox.Sandbox{}, core.ErrNotFound
	}
	if err != nil {
		return sandbox.Sandbox{}, err
	}
	sb.CreatedAt = fromUnix(created)
	sb.UpdatedAt = fromUnix(updated)
	return sb, nil
}

// List returns one page of sandboxes.
func (s *Store) List(ctx context.Context, opts sandbox.ListOptions) ([]sandbox.Sandbox, string, error) {
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	offset, err := decodeOffset(opts.PageToken)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, state, generation, image, workspace, error, created_at, updated_at
		FROM sandboxes ORDER BY created_at, id LIMIT ? OFFSET ?`, pageSize+1, offset)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var out []sandbox.Sandbox
	for rows.Next() {
		var sb sandbox.Sandbox
		var created, updated int64
		if err := rows.Scan(&sb.ID, &sb.Name, &sb.State, &sb.Generation, &sb.Image, &sb.Workspace, &sb.Error, &created, &updated); err != nil {
			return nil, "", err
		}
		sb.CreatedAt = fromUnix(created)
		sb.UpdatedAt = fromUnix(updated)
		out = append(out, sb)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > pageSize {
		out = out[:pageSize]
		next = encodeOffset(offset + pageSize)
	}
	return out, next, nil
}

// Update updates a sandbox.
func (s *Store) Update(ctx context.Context, sb sandbox.Sandbox) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sandboxes SET name=?, state=?, generation=?, image=?, workspace=?, error=?, updated_at=?
		WHERE id=?`,
		sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, sb.Error, toUnix(sb.UpdatedAt), sb.ID)
	if err != nil {
		return mapSQLError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Delete deletes a sandbox.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sandboxes WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Create inserts an operation.
func (s *OperationStore) Create(opCtx context.Context, op operation.Operation) error {
	_, err := s.db.ExecContext(opCtx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt))
	return mapSQLError(err)
}

// Get returns an operation by ID.
func (s *OperationStore) Get(ctx context.Context, id string) (operation.Operation, error) {
	var op operation.Operation
	var created, updated int64
	err := s.db.QueryRowContext(ctx, `SELECT id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at
		FROM operations WHERE id=?`, id).Scan(
		&op.ID, &op.SandboxID, &op.Kind, &op.State, &op.Generation, &op.IdempotencyKey, &op.Error, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return operation.Operation{}, core.ErrNotFound
	}
	if err != nil {
		return operation.Operation{}, err
	}
	op.CreatedAt = fromUnix(created)
	op.UpdatedAt = fromUnix(updated)
	return op, nil
}

// ListBySandbox returns operations for a sandbox.
func (s *OperationStore) ListBySandbox(ctx context.Context, sandboxID string) ([]operation.Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at
		FROM operations WHERE sandbox_id=? ORDER BY created_at, id`, sandboxID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []operation.Operation
	for rows.Next() {
		var op operation.Operation
		var created, updated int64
		if err := rows.Scan(&op.ID, &op.SandboxID, &op.Kind, &op.State, &op.Generation, &op.IdempotencyKey, &op.Error, &created, &updated); err != nil {
			return nil, err
		}
		op.CreatedAt = fromUnix(created)
		op.UpdatedAt = fromUnix(updated)
		out = append(out, op)
	}
	return out, rows.Err()
}

// Update updates an operation.
func (s *OperationStore) Update(ctx context.Context, op operation.Operation) error {
	res, err := s.db.ExecContext(ctx, `UPDATE operations SET state=?, generation=?, error=?, updated_at=? WHERE id=?`,
		op.State, op.Generation, op.Error, toUnix(op.UpdatedAt), op.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

// CreateSandboxWithOperation inserts a sandbox and its operation atomically.
func (s *Store) CreateSandboxWithOperation(ctx context.Context, sb sandbox.Sandbox, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO sandboxes
		(id, name, state, generation, image, workspace, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		sb.ID, sb.Name, sb.State, sb.Generation, sb.Image, sb.Workspace, sb.Error,
		toUnix(sb.CreatedAt), toUnix(sb.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// ApplySandboxOperation updates a sandbox and appends an operation atomically.
func (s *Store) ApplySandboxOperation(ctx context.Context, sb sandbox.Sandbox, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE sandboxes SET state=?, generation=?, error=?, updated_at=? WHERE id=?`,
		sb.State, sb.Generation, sb.Error, toUnix(sb.UpdatedAt), sb.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// DeleteSandboxWithOperation deletes a sandbox and appends an operation atomically.
func (s *Store) DeleteSandboxWithOperation(ctx context.Context, id string, op operation.Operation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM sandboxes WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return core.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations
		(id, sandbox_id, kind, state, generation, idempotency_key, error, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		op.ID, op.SandboxID, op.Kind, op.State, op.Generation, op.IdempotencyKey, op.Error,
		toUnix(op.CreatedAt), toUnix(op.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return core.ErrConflict
	}
	return err
}

func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func encodeOffset(n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(n)))
}

func decodeOffset(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, fmt.Errorf("invalid page token: %w", err)
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid page token")
	}
	return n, nil
}
