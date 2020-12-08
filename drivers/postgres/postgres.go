package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Postgres struct {
	db *sql.DB
}

// New return *Postgres
func New(db *sql.DB) (*Postgres, error) {
	return &Postgres{
		db: db,
	}, nil
}

func (m *Postgres) CreateIfNotExistTables(ctx context.Context) error {
	var count int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('vulnerabilities', 'vulnerability_advisories');`).Scan(&count); err != nil {
		return err
	}
	switch count {
	case 2:
		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	if _, err := m.db.Exec(`CREATE TABLE vulnerabilities (
id serial PRIMARY KEY,
vulnerability_id varchar (25) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`COMMENT ON TABLE vulnerabilities IS 'vulnerabilities obtained via Trivy DB';`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX v_vulnerability_id_idx ON vulnerabilities(vulnerability_id);`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE TABLE vulnerability_advisories (
id serial PRIMARY KEY,
vulnerability_id varchar (25) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`COMMENT ON TABLE vulnerability_advisories IS 'vulnerability advisories obtained via Trivy DB';`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_vulnerability_advisories_idx ON vulnerability_advisories(vulnerability_id, platform, segment, package)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_vulnerability_id_idx ON vulnerability_advisories(vulnerability_id)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_platform_idx ON vulnerability_advisories(platform)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_source_idx ON vulnerability_advisories(platform, segment)`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_source_package_idx ON vulnerability_advisories(platform, segment, package)`); err != nil {
		return err
	}

	return nil
}

func (m *Postgres) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	iv := []string{}
	for i := 0; i < len(vulns); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2))
	}
	query := fmt.Sprintf("INSERT INTO vulnerabilities(vulnerability_id,value) VALUES %s", strings.Join(iv, ",")) // #nosec

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

func (m *Postgres) InsertVulnAdvisory(ctx context.Context, vulnds [][][]byte) error {
	iv := []string{}
	for i := 0; i < len(vulnds); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
	}
	query := fmt.Sprintf("INSERT INTO vulnerability_advisories(vulnerability_id,platform,segment,package,value) VALUES %s", strings.Join(iv, ",")) // #nosec
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

func (m *Postgres) TruncateVulns(ctx context.Context) error {
	if _, err := m.db.Exec(`TRUNCATE TABLE vulnerabilities;`); err != nil {
		return err
	}
	return nil
}

func (m *Postgres) TruncateVulnAdvisories(ctx context.Context) error {
	if _, err := m.db.Exec(`TRUNCATE TABLE vulnerability_advisories;`); err != nil {
		return err
	}
	return nil
}
