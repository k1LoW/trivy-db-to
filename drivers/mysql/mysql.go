package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Mysql struct {
	db                       *sql.DB
	vulnerabilitiesTableName string
	adivosryTableName        string
}

// New return *Mysql
func New(db *sql.DB, vulnerabilitiesTableName, adivosryTableName string) (*Mysql, error) {
	return &Mysql{
		db:                       db,
		vulnerabilitiesTableName: vulnerabilitiesTableName,
		adivosryTableName:        adivosryTableName,
	}, nil
}

func (m *Mysql) CreateIfNotExistTables(ctx context.Context) error {
	var count int
	stmt := fmt.Sprintf("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database() AND table_name IN ('%s', '%s');", m.vulnerabilitiesTableName, m.adivosryTableName) // #nosec
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
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (128) NOT NULL,
value json NOT NULL,
created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) COMMENT = 'vulnerabilities obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, m.vulnerabilitiesTableName)

	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX v_vulnerability_id_idx ON %s(vulnerability_id) USING BTREE;`, m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE TABLE %s (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (128) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP
) COMMENT = 'vulnerability advisories obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, m.adivosryTableName)

	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_vulnerability_advisories_idx ON %s(vulnerability_id, platform, segment, package) USING BTREE;`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_vulnerability_id_idx ON %s(vulnerability_id) USING BTREE;`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_platform_idx ON %s(platform) USING BTREE;`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_source_idx ON %s(platform, segment) USING BTREE;`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	stmt = fmt.Sprintf(`CREATE INDEX va_source_package_idx ON %s(platform, segment, package) USING BTREE;`, m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}

	return nil
}

func (m *Mysql) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,value) VALUES (?,?)%s", m.vulnerabilitiesTableName, strings.Repeat(", (?,?)", len(vulns)-1)) // #nosec

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

func (m *Mysql) InsertVulnAdvisory(ctx context.Context, vulnds [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO %s(vulnerability_id,platform,segment,package,value) VALUES (?,?,?,?,?)%s", m.adivosryTableName, strings.Repeat(", (?,?,?,?,?)", len(vulnds)-1)) // #nosec
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

func (m *Mysql) TruncateVulns(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.vulnerabilitiesTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}

func (m *Mysql) TruncateVulnAdvisories(ctx context.Context) error {
	stmt := fmt.Sprintf("TRUNCATE TABLE %s;", m.adivosryTableName)
	if _, err := m.db.Exec(stmt); err != nil {
		return err
	}
	return nil
}
