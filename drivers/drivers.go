package drivers

type Driver interface {
	CreateTable() error
	InsertVuln(vulns [][][]byte) error
	InsertVulnDetail(vulnds [][][]byte) error
}
