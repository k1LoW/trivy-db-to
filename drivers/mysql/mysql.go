package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type Mysql struct {
	db *sql.DB
}

// New return *Mysql
func New(db *sql.DB) (*Mysql, error) {
	return &Mysql{
		db: db,
	}, nil
}

func (m *Mysql) CreateIfNotExistTables(ctx context.Context) error {
	var count int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database() AND table_name IN ('vulnerabilities', 'vulnerability_advisories');`).Scan(&count); err != nil {
		return err
	}
	switch count {
	case 2:
		return nil
	case 1:
		return errors.New("invalid table schema")
	}

	if _, err := m.db.Exec(`CREATE TABLE vulnerabilities (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (25) NOT NULL,
value json NOT NULL,
created timestamp NOT NULL
) COMMENT = 'vulnerabilities obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX v_vulnerability_id_idx ON vulnerabilities(vulnerability_id) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE TABLE vulnerability_advisories (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (25) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created timestamp NOT NULL
) COMMENT = 'vulnerability advisories obtained via Trivy DB' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_vulnerability_advisories_idx ON vulnerability_advisories(vulnerability_id, platform, segment, package) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_vulnerability_id_idx ON vulnerability_advisories(vulnerability_id) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_platform_idx ON vulnerability_advisories(platform) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_source_idx ON vulnerability_advisories(platform, segment) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX va_source_package_idx ON vulnerability_advisories(platform, segment, package) USING BTREE;`); err != nil {
		return err
	}

	return nil
}

func (m *Mysql) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO vulnerabilities(vulnerability_id,value) VALUES (?,?)%s", strings.Repeat(", (?,?)", len(vulns)-1)) // #nosec

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

func (m *Mysql) InsertVulnDetail(ctx context.Context, vulnds [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO vulnerability_advisories(vulnerability_id,platform,segment,package,value) VALUES (?,?,?,?,?)%s", strings.Repeat(", (?,?,?,?,?)", len(vulnds)-1)) // #nosec
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
	return nil
}

func (m *Mysql) TruncateVulns(ctx context.Context) error {
	if _, err := m.db.Exec(`TRUNCATE TABLE vulnerabilities;`); err != nil {
		return err
	}
	return nil
}

func (m *Mysql) TruncateVulnAdvisories(ctx context.Context) error {
	if _, err := m.db.Exec(`TRUNCATE TABLE vulnerability_advisories;`); err != nil {
		return err
	}
	return nil
}
