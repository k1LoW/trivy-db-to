package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/indicator"
	"github.com/k1LoW/trivy-db-to/drivers"
	"github.com/k1LoW/trivy-db-to/drivers/mysql"
	"github.com/k1LoW/trivy-db-to/drivers/postgres"
	"github.com/k1LoW/trivy-db-to/version"
	"github.com/spf13/afero"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
	"k8s.io/utils/clock"
)

const chunkSize = 100

func FetchTrivyDB(ctx context.Context, cacheDir string, light, quiet, skipUpdate bool) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Fetching and updating Trivy DB ... ")
	config := db2.Config{}
	client := github.NewClient()
	progressBar := indicator.NewProgressBar(quiet)
	realClock := clock.RealClock{}
	fs := afero.NewOsFs()
	metadata := db.NewMetadata(fs, cacheDir)
	dbClient := db.NewClient(config, client, progressBar, realClock, metadata)
	needsUpdate, err := dbClient.NeedsUpdate(version.Version, light, skipUpdate)
	if err != nil {
		return err
	}
	if needsUpdate {
		_, _ = fmt.Fprint(os.Stderr, "\n")
		if err := dbClient.Download(ctx, cacheDir, light); err != nil {
			return err
		}
		if err := dbClient.UpdateMetadata(cacheDir); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done (already exist)")
	}
	return nil
}

func InitDB(ctx context.Context, dsn, vulnerabilityTableName, advisoryTableName string) error {
	var (
		driver drivers.Driver
		err    error
	)
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Initializing vulnerability information tables ... ")
	u, err := dburl.Parse(dsn)
	if err != nil {
		return err
	}
	db, err := dburl.Open(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch u.Driver {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", u.Driver)
	}

	if err := driver.CreateIfNotExistTables(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	return nil
}

func UpdateDB(ctx context.Context, cacheDir, dsn, vulnerabilityTableName, advisoryTableName string) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Updating vulnerability information tables ... \n")
	var (
		driver drivers.Driver
		err    error
	)

	u, err := dburl.Parse(dsn)
	if err != nil {
		return err
	}
	db, err := dburl.Open(dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	switch u.Driver {
	case "mysql":
		driver, err = mysql.New(db, vulnerabilityTableName, advisoryTableName)
		if err != nil {
			return err
		}
	case "postgres":
		driver, err = postgres.New(db)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", u.Driver)
	}

	trivydb, err := bolt.Open(filepath.Join(cacheDir, "db", "trivy.db"), 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	defer trivydb.Close()

	if err := trivydb.View(func(tx *bolt.Tx) error {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", ">> Updating table 'vulnerabilities' ... ")
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

		_, _ = fmt.Fprintf(os.Stderr, "%s\n", ">> Update table 'vulnerability_advisories' ... ")
		if err := driver.TruncateVulnAdvisories(ctx); err != nil {
			return err
		}
		if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
			s := string(source)
			if s == "trivy" || s == "vulnerability" {
				return nil
			}
			_, _ = fmt.Fprintf(os.Stderr, ">>> %s\n", s)
			c := b.Cursor()
			vulnds := [][][]byte{}
			for pkg, _ := c.First(); pkg != nil; pkg, _ = c.Next() {
				cb := b.Bucket(pkg)
				cbc := cb.Cursor()
				for vID, v := cbc.First(); vID != nil; vID, v = cbc.Next() {
					platform := []byte(s)
					segment := []byte("")
					splited := strings.Split(s, " ")
					if len(splited) > 1 {
						platform = []byte(strings.Join(splited[0:len(splited)-1], " "))
						segment = []byte(splited[len(splited)-1])
					}
					vulnds = append(vulnds, [][]byte{vID, platform, segment, pkg, v})
				}
				if len(vulnds) > chunkSize {
					if err := driver.InsertVulnAdvisory(ctx, vulnds); err != nil {
						return err
					}
					vulnds = [][][]byte{}
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
