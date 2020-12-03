package mysql

import (
	"context"
	"database/sql"
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

func (m *Mysql) CreateTable(ctx context.Context) error {
	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (25) NOT NULL,
vuln json NOT NULL,
created timestamp NOT NULL
) COMMENT = 'vulnerability details via trivy-db' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS v_vulnerability_id_idx ON vulnerabilities(vulnerability_id) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS vulnerability_details (
id int PRIMARY KEY AUTO_INCREMENT,
vulnerability_id varchar (25) NOT NULL,
platform varchar (50) NOT NULL,
segment varchar (50) NOT NULL,
package varchar (100) NOT NULL,
value json NOT NULL,
created timestamp NOT NULL
) COMMENT = 'vulnerability details via trivy-db' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS vd_vulnerability_details_idx ON vulnerability_details(vulnerability_id, platform, segment, package) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS vd_vulnerability_id_idx ON vulnerability_details(vulnerability_id) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS vd_platform_idx ON vulnerability_details(platform) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS vd_source_idx ON vulnerability_details(platform, segment) USING BTREE;`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX IF NOT EXISTS vd_source_package_idx ON vulnerability_details(platform, segment, package) USING BTREE;`); err != nil {
		return err
	}

	return nil
}

func (m *Mysql) InsertVuln(ctx context.Context, vulns [][][]byte) error {
	query := fmt.Sprintf("INSERT INTO vulnerabilities(vulnerability_id,vuln) VALUES (?,?)%s", strings.Repeat(", (?,?)", len(vulns)-1))

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
	query := fmt.Sprintf("INSERT INTO vulnerability_details(vulnerability_id,platform,segment,package,value) VALUES (?,?,?,?,?)%s", strings.Repeat(", (?,?,?,?,?)", len(vulnds)-1))
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
