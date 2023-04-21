package drivers

import "context"

type Driver interface {
	Migrate(ctx context.Context) error
	InsertVuln(ctx context.Context, vulns [][][]byte) error
	InsertVulnAdvisory(ctx context.Context, vulnds [][][]byte) error
	TruncateVulns(ctx context.Context) error
	TruncateVulnAdvisories(ctx context.Context) error
}
