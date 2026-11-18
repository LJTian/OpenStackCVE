package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"OpenStackCVE/internal/model"
	"OpenStackCVE/internal/normalize"
)

const schema = `
CREATE TABLE IF NOT EXISTS cves (
  cve_id       TEXT PRIMARY KEY,
  title        TEXT,
  summary      TEXT,
  components   TEXT,
  severity     TEXT,
  published_at TEXT,
  refs         TEXT,
  source       TEXT,
  raw          TEXT,
  fetched_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_published ON cves(published_at);
CREATE INDEX IF NOT EXISTS idx_source ON cves(source);
CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity);

CREATE TABLE IF NOT EXISTS cve_components (
  cve_id    TEXT NOT NULL,
  component TEXT NOT NULL,
  PRIMARY KEY (cve_id, component)
);
`

// DB wraps sqlite access.
type DB struct {
	SQL *sql.DB
}

// Open opens (and creates parent dir for) the sqlite file.
func Open(dsn string, filePath string) (*DB, error) {
	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return &DB{SQL: sqlDB}, nil
}

func (d *DB) Close() error {
	return d.SQL.Close()
}

// Migrate creates tables and indexes.
func (d *DB) Migrate(ctx context.Context) error {
	_, err := d.SQL.ExecContext(ctx, schema)
	return err
}

// Get returns one CVE by id, or nil if missing.
func (d *DB) Get(ctx context.Context, cveID string) (*model.CVE, string, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	row := d.SQL.QueryRowContext(ctx, `
SELECT cve_id, title, summary, components, severity, published_at, refs, source, raw, fetched_at
FROM cves WHERE cve_id = ?`, cveID)

	var (
		item      model.CVE
		compJSON  string
		refsJSON  string
		published string
		fetched   string
		raw       sql.NullString
	)
	err := row.Scan(
		&item.CVEID, &item.Title, &item.Summary, &compJSON, &item.Severity,
		&published, &refsJSON, &item.Source, &raw, &fetched,
	)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	_ = json.Unmarshal([]byte(compJSON), &item.Components)
	_ = json.Unmarshal([]byte(refsJSON), &item.Refs)
	if item.Components == nil {
		item.Components = []string{}
	}
	if item.Refs == nil {
		item.Refs = []string{}
	}
	if published != "" {
		if t, err := time.Parse(time.RFC3339, published); err == nil {
			item.PublishedAt = &t
		}
	}
	if t, err := time.Parse(time.RFC3339, fetched); err == nil {
		item.FetchedAt = t
	}
	return &item, raw.String, nil
}

// Upsert inserts or updates a CVE and refreshes component index rows.
func (d *DB) Upsert(ctx context.Context, cve model.CVE, raw string) error {
	return d.upsert(ctx, cve, raw, false)
}

// UpsertMerged merges with an existing row (same cve_id) before writing.
func (d *DB) UpsertMerged(ctx context.Context, cve model.CVE, raw string) error {
	return d.upsert(ctx, cve, raw, true)
}

func (d *DB) upsert(ctx context.Context, cve model.CVE, raw string, merge bool) error {
	if cve.CVEID == "" {
		return fmt.Errorf("cve_id is required")
	}
	cve.CVEID = strings.ToUpper(strings.TrimSpace(cve.CVEID))

	if merge {
		existing, oldRaw, err := d.Get(ctx, cve.CVEID)
		if err != nil {
			return err
		}
		if existing != nil {
			cve = normalize.MergeCVE(*existing, cve)
			if oldRaw != "" && strings.Contains(strings.ToLower(existing.Source), "ossa") {
				raw = oldRaw
			} else if oldRaw != "" && raw == "" {
				raw = oldRaw
			}
		}
	}

	if cve.Components == nil {
		cve.Components = []string{}
	}
	if cve.Refs == nil {
		cve.Refs = []string{}
	}

	compJSON, err := json.Marshal(cve.Components)
	if err != nil {
		return err
	}
	refsJSON, err := json.Marshal(cve.Refs)
	if err != nil {
		return err
	}

	published := ""
	if cve.PublishedAt != nil {
		published = cve.PublishedAt.UTC().Format(time.RFC3339)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	fetched := cve.FetchedAt.UTC().Format(time.RFC3339)
	if cve.FetchedAt.IsZero() {
		fetched = now
	}

	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
INSERT INTO cves (
  cve_id, title, summary, components, severity,
  published_at, refs, source, raw, fetched_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(cve_id) DO UPDATE SET
  title=excluded.title,
  summary=excluded.summary,
  components=excluded.components,
  severity=excluded.severity,
  published_at=excluded.published_at,
  refs=excluded.refs,
  source=excluded.source,
  raw=excluded.raw,
  fetched_at=excluded.fetched_at,
  updated_at=excluded.updated_at;
`, cve.CVEID, cve.Title, cve.Summary, string(compJSON), cve.Severity,
		published, string(refsJSON), cve.Source, raw, fetched, now)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM cve_components WHERE cve_id = ?`, cve.CVEID); err != nil {
		return err
	}
	for _, comp := range cve.Components {
		comp = strings.TrimSpace(comp)
		if comp == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO cve_components(cve_id, component) VALUES (?, ?)`,
			cve.CVEID, comp); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryFilter holds optional query constraints.
type QueryFilter struct {
	CVEID     string
	Component string
	Since     string
	Severity  string
	Limit     int
}

// Query returns CVEs matching filters.
func (d *DB) Query(ctx context.Context, f QueryFilter) ([]model.CVE, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	var (
		args  []interface{}
		where []string
	)
	where = append(where, "1=1")

	if f.CVEID != "" {
		where = append(where, "c.cve_id = ?")
		args = append(args, strings.ToUpper(strings.TrimSpace(f.CVEID)))
	}
	if f.Severity != "" {
		where = append(where, "lower(c.severity) = lower(?)")
		args = append(args, strings.TrimSpace(f.Severity))
	}
	if f.Since != "" {
		since, err := normalizeSince(f.Since)
		if err != nil {
			return nil, err
		}
		where = append(where, "c.published_at != '' AND c.published_at >= ?")
		args = append(args, since)
	}
	if f.Component != "" {
		where = append(where, `EXISTS (
			SELECT 1 FROM cve_components cc
			WHERE cc.cve_id = c.cve_id AND lower(cc.component) = lower(?)
		)`)
		args = append(args, strings.TrimSpace(f.Component))
	}

	q := fmt.Sprintf(`
SELECT c.cve_id, c.title, c.summary, c.components, c.severity,
       c.published_at, c.refs, c.source, c.fetched_at
FROM cves c
WHERE %s
ORDER BY c.published_at DESC, c.cve_id DESC
LIMIT ?`, strings.Join(where, " AND "))
	args = append(args, f.Limit)

	rows, err := d.SQL.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.CVE
	for rows.Next() {
		var (
			item      model.CVE
			compJSON  string
			refsJSON  string
			published string
			fetched   string
		)
		if err := rows.Scan(
			&item.CVEID, &item.Title, &item.Summary, &compJSON, &item.Severity,
			&published, &refsJSON, &item.Source, &fetched,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(compJSON), &item.Components)
		_ = json.Unmarshal([]byte(refsJSON), &item.Refs)
		if item.Components == nil {
			item.Components = []string{}
		}
		if item.Refs == nil {
			item.Refs = []string{}
		}
		if published != "" {
			if t, err := time.Parse(time.RFC3339, published); err == nil {
				item.PublishedAt = &t
			}
		}
		if t, err := time.Parse(time.RFC3339, fetched); err == nil {
			item.FetchedAt = t
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []model.CVE{}
	}
	return out, nil
}

func normalizeSince(s string) (string, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid --since value %q (use YYYY-MM-DD or RFC3339)", s)
}
