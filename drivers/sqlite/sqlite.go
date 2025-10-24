package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Sqlite struct {
	db                       *sql.DB
	vulnerabilitiesTableName string
	advisoryTableName        string
}

// New return *Sqlite.
func New(db *sql.DB, vulnerabilitiesTableName, adviosryTableName string) (*Sqlite, error) {
	if _, err := db.Exec(`
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
    `); err != nil {
		return nil, err
	}

	return &Sqlite{
		db:                       db,
		vulnerabilitiesTableName: vulnerabilitiesTableName,
		advisoryTableName:        adviosryTableName,
	}, nil
}

func (m *Sqlite) Migrate(ctx context.Context) error {
	var count int
	stmt := fmt.Sprintf("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('%s', '%s');", m.vulnerabilitiesTableName, m.advisoryTableName) //nolint:gosec

	if err := m.db.QueryRowContext(ctx, stmt).Scan(&count); err != nil {
		return err
	}

	switch count {
	case 2:
		// Migrate from v1
		stmt = fmt.Sprintf(`PRAGMA foreign_keys=off;
            BEGIN TRANSACTION;
            CREATE TEMPORARY TABLE %s_backup(id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id TEXT, value TEXT, created_at TIMESTAMP);
            INSERT INTO %s_backup SELECT * FROM %s;
            DROP TABLE %s;
            CREATE TABLE %s(id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id TEXT, value TEXT, created_at TIMESTAMP);
            INSERT INTO %s SELECT * FROM %s_backup;
            DROP TABLE %s_backup;
            COMMIT;
            PRAGMA foreign_keys=on;`, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName, m.vulnerabilitiesTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}

		stmt = fmt.Sprintf(`PRAGMA foreign_keys=off;
            BEGIN TRANSACTION;
            CREATE TEMPORARY TABLE %s_backup(id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id TEXT, platform TEXT, segment TEXT, package TEXT, value TEXT, created_at TIMESTAMP);
            INSERT INTO %s_backup SELECT * FROM %s;
            DROP TABLE %s;
            CREATE TABLE %s(id INTEGER PRIMARY KEY AUTOINCREMENT, vulnerability_id TEXT, platform TEXT, segment TEXT, package TEXT, value TEXT, created_at TIMESTAMP);
            INSERT INTO %s SELECT * FROM %s_backup;
            DROP TABLE %s_backup;
            COMMIT;
            PRAGMA foreign_keys=on;`, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName, m.advisoryTableName)
		if _, err := m.db.Exec(stmt); err != nil {
			return err
		}

		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	return m.createTables(ctx)
}

func (m *Sqlite) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	iv := []string{}
	for i := 0; i < len(vulns); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2))
	}
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,value) VALUES %s", m.vulnerabilitiesTableName, strings.Join(iv, ",")) //nolint:gosec

	ins, err := m.db.Prepare(query)
	if err != nil {
		return err
	}

	values := []interface{}{}
	for _, vuln := range vulns {
		values = append(values, vuln[0], vuln[1])
	}
	{
		_, err := ins.Exec(values...)
		return err
	}
}

func (m *Sqlite) InsertVulnAdvisory(ctx context.Context, vulnds [][][]byte) error {
	iv := []string{}
	for i := 0; i < len(vulnds); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
	}

	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,platform,segment,package,value) VALUES %s", m.advisoryTableName, strings.Join(iv, ",")) //nolint:gosec
	ins, err := m.db.Prepare(query)
	if err != nil {
		return err
	}

	values := []interface{}{}
	for _, vuln := range vulnds {
		values = append(values, vuln[0], vuln[1], vuln[2], vuln[3], vuln[4])
	}
	{
		_, err := ins.Exec(values...)
		return err
	}
}

func (m *Sqlite) TruncateVulns(ctx context.Context) error {
	stmt := fmt.Sprintf("DROP TABLE IF EXISTS %s;", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return m.createVulnerabilitiesTable(ctx)
}

func (m *Sqlite) TruncateVulnAdvisories(ctx context.Context) error {
	stmt := fmt.Sprintf("DROP TABLE IF EXISTS %s;", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return m.createAdvisoryTable(ctx)
}

func (m *Sqlite) createTables(ctx context.Context) error {
	if err := m.createVulnerabilitiesTable(ctx); err != nil {
		return err
	}

	if err := m.createAdvisoryTable(ctx); err != nil {
		return err
	}

	return nil
}

func (m *Sqlite) createVulnerabilitiesTable(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id TEXT NOT NULL,
        value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`, m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS v_vulnerability_id_idx ON %s(vulnerability_id);", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return nil
}

func (m *Sqlite) createAdvisoryTable(ctx context.Context) error {
	stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id TEXT NOT NULL,
        platform TEXT NOT NULL,
        segment TEXT NOT NULL,
        package TEXT NOT NULL,
        value TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`, m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS va_vulnerability_advisories_idx ON %s(vulnerability_id, platform, segment, package);", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS va_vulnerability_id_idx ON %s(vulnerability_id);", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS va_platform_idx ON %s(platform);", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS va_source_idx ON %s(platform, segment);", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX IF NOT EXISTS va_source_package_idx ON %s(platform, segment, package);", m.advisoryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}
