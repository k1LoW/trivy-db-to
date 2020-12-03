package drivers

import "context"

type Driver interface {
	CreateTable(ctx context.Context) error
	InsertVuln(ctx context.Context, vulns [][][]byte) error
	InsertVulnDetail(ctx context.Context, vulnds [][][]byte) error
}
