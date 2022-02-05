package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Postgres struct {
	db                       *sql.DB
	vulnerabilitiesTableName string
	adivosryTableName        string
}

// New return *Postgres
func New(db *sql.DB, vulnerabilitiesTableName, adivosryTableName string) (*Postgres, error) {
	return &Postgres{
		db:                       db,
		vulnerabilitiesTableName: vulnerabilitiesTableName,
		adivosryTableName:        adivosryTableName,
	}, nil
}

func (m *Postgres) CreateIfNotExistTables(ctx context.Context) error {
	var count int
	stmt := fmt.Sprintf("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('%s', '%s');", m.vulnerabilitiesTableName, m.adivosryTableName) // #nosec
	if err := m.db.QueryRowContext(ctx, stmt).Scan(&count); err != nil {
		return err
	}
	switch count {
	case 2:
		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id serial PRIMARY KEY,
vulnerability_id varchar (25) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("COMMENT ON TABLE %s IS 'vulnerability obtained via Trivy DB';", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX v_vulnerability_id_idx ON %s(vulnerability_id);", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id serial PRIMARY KEY,
vulnerability_id varchar (25) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
)`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`COMMENT ON TABLE %s IS 'vulnerability advisories obtained via Trivy DB';`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_vulnerability_advisories_idx ON %s(vulnerability_id, platform, segment, package)", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_vulnerability_id_idx ON %s(vulnerability_id)", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_platform_idx ON %s(platform)", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_source_idx ON %s(platform, segment)", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf("CREATE INDEX va_source_package_idx ON %s(platform, segment, package)", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return nil
}

func (m *Postgres) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	iv := []string{}
	for i := 0; i < len(vulns); i++ {
		iv = append(iv, fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2))
	}
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,value) VALUES %s", m.vulnerabilitiesTableName, strings.Join(iv, ",")) // #nosec

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
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,platform,segment,package,value) VALUES %s", m.adivosryTableName, strings.Join(iv, ",")) // #nosec
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
	stmt := fmt.Sprintf("TRUNCATE TABLE %s", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

func (m *Postgres) TruncateVulnAdvisories(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}
