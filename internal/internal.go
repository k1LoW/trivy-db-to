package internal

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/k1LoW/trivy-db-to/drivers"
	"github.com/k1LoW/trivy-db-to/drivers/mysql"
	"github.com/k1LoW/trivy-db-to/drivers/postgres"
	"github.com/k1LoW/trivy-db-to/drivers/sqlite"
	"github.com/samber/lo"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
)

const chunkSize = 5000

func FetchTrivyDB(ctx context.Context, cacheDir string, light, quiet, skipUpdate bool) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Fetching and updating Trivy DB ... \n")
	appVersion := "99.9.9"
	dbRepository := "ghcr.io/aquasecurity/trivy-db"
	dbPath := db2.Path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return err
	}

	// Parse repository string to name.Reference
	ref, err := name.ParseReference(dbRepository)
	if err != nil {
		return fmt.Errorf("failed to parse repository: %w", err)
	}

	client := db.NewClient(cacheDir, quiet, db.WithDBRepository([]name.Reference{ref}))
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, skipUpdate)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}

	if needsUpdate {
		_, _ = fmt.Fprintln(os.Stderr, "Need to update DB")
		_, _ = fmt.Fprintf(os.Stderr, "DB Repository: %s\n", dbRepository)
		_, _ = fmt.Fprintln(os.Stderr, "Downloading DB...")
		if err = client.Download(ctx, cacheDir, types.RegistryOptions{}); err != nil {
			return fmt.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	_, _ = fmt.Fprintln(os.Stderr, "done")

	return nil
}

func InitDB(ctx context.Context, dsn, vulnerabilityTableName, advisoryTableName string) error {
	var (
		driver drivers.Driver
		err    error
	)
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Initializing vulnerability information tables ... ")
	db, d, err := dbOpen(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch d {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "sqlite":
		driver, err = sqlite.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", d)
	}

	if err := driver.Migrate(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(os.Stderr, "done")
	return nil
}

func UpdateDB(ctx context.Context, cacheDir, dsn, vulnerabilityTableName, advisoryTableName string, targetSources []string) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Updating vulnerability information tables ... \n")
	var (
		driver drivers.Driver
		err    error
	)

	db, d, err := dbOpen(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch d {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "sqlite":
		driver, err = sqlite.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", d)
	}

	trivydb, err := bolt.Open(filepath.Join(cacheDir, "trivy.db"), 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	defer trivydb.Close()

	if err := trivydb.View(func(tx *bolt.Tx) error {
		_, _ = fmt.Fprintf(os.Stderr, ">> Updating table '%s' ...\n", vulnerabilityTableName)
		if err := driver.TruncateVulns(ctx); err != nil {
			return err
		}
		b := tx.Bucket([]byte("vulnerability"))
		c := b.Cursor()
		started := false
		ended := false
		for {
			vulns := [][][]byte{}
			if !started {
				k, v := c.First()
				vulns = append(vulns, [][]byte{k, v})
				started = true
			}
			for i := 0; i < chunkSize; i++ {
				k, v := c.Next()
				if k == nil {
					ended = true
					break
				}
				vulns = append(vulns, [][]byte{k, v})
			}
			if len(vulns) > 0 {
				if err := driver.InsertVuln(ctx, vulns); err != nil {
					return err
				}
			}
			if ended {
				break
			}
		}

		sourceRe := []*regexp.Regexp{}
		for _, s := range targetSources {
			re, err := regexp.Compile(s)
			if err != nil {
				return err
			}
			sourceRe = append(sourceRe, re)
		}

		_, _ = fmt.Fprintf(os.Stderr, ">> Updating table '%s' ...\n", advisoryTableName)
		if err := driver.TruncateVulnAdvisories(ctx); err != nil {
			return err
		}
		if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
			s := string(source)
			if s == "trivy" || s == "vulnerability" {
				return nil
			}

			if len(sourceRe) > 0 {
				found := false
				for _, re := range sourceRe {
					if re.MatchString(s) {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}

			_, _ = fmt.Fprintf(os.Stderr, ">>> %s\n", s)
			c := b.Cursor()
			vulnds := [][][]byte{}
			for pkg, _ := c.First(); pkg != nil; pkg, _ = c.Next() {
				cb := b.Bucket(pkg)
				if cb == nil {
					continue
				}
				cbc := cb.Cursor()
				for vID, v := cbc.First(); vID != nil; vID, v = cbc.Next() {
					platform, segment := parsePlatformAndSegment(s)
					vulnds = append(vulnds, [][]byte{vID, platform, segment, pkg, v})
				}
			}
			chunked := lo.Chunk(vulnds, chunkSize)
			for _, c := range chunked {
				if err := driver.InsertVulnAdvisory(ctx, c); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	return nil
}

func dbOpen(dsn string) (*sql.DB, string, error) {
	u, err := dburl.Parse(dsn)
	if err != nil {
		return nil, "", err
	}
	if u.Driver == "sqlite3" {
		u.Driver = "sqlite"
	}
	db, err := sql.Open(u.Driver, u.DSN)
	if err != nil {
		return nil, "", err
	}
	return db, u.Driver, nil
}

var numRe = regexp.MustCompile(`\d+`)

func parsePlatformAndSegment(s string) ([]byte, []byte) {
	const alpineEdgeSegment = "edge"
	platform := []byte(s)
	segment := []byte("")
	splited := strings.Split(s, " ")
	if len(splited) > 1 {
		last := splited[len(splited)-1]
		if numRe.MatchString(last) || last == alpineEdgeSegment {
			platform = []byte(strings.Join(splited[0:len(splited)-1], " "))
			segment = []byte(last)
		}
	}
	return platform, segment
}
