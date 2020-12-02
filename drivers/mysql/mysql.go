package mysql

import "database/sql"

type Mysql struct {
	db *sql.DB
}

// New return *Mysql
func New(db *sql.DB) (*Mysql, error) {
	return &Mysql{
		db: db,
	}, nil
}

func (m *Mysql) CreateTable() error {
	if _, err := m.db.Exec(`CREATE TABLE vulnerabilities (
vulnerability_id varchar (50) NOT NULL,
source varchar (50) NOT NULL,
value json NOT NULL,
created timestamp NOT NULL,
CONSTRAINT vulnerability_id_source_pk PRIMARY KEY(vulnerability_id, source)
) COMMENT = 'vulnerabilities via trivy-db' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		return err
	}

	if _, err := m.db.Exec(`CREATE INDEX vulnerability_id_idx ON vulnerabilities(vulnerability_id) USING BTREE;`); err != nil {
		return err
	}

	return nil
}
