/*
Copyright © 2020 Ken'ichiro Oyama <k1lowxb@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

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
	trivylog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/k1LoW/trivy-db-to/drivers"
	"github.com/k1LoW/trivy-db-to/drivers/mysql"
	"github.com/k1LoW/trivy-db-to/version"
	"github.com/shibukawa/configdir"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
	"k8s.io/utils/clock"
)

const chunkSize = 100

var (
	quiet      bool
	light      bool
	skipUpdate bool
	cacheDir   string
)

var rootCmd = &cobra.Command{
	Use:          "trivy-db-to",
	Short:        "Tool for migrating/converting from trivy-db to RDBMS",
	Long:         `Tool for migrating/converting from trivy-db to RDBMS.`,
	SilenceUsage: true,
	Version:      version.Version,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		if cacheDir == "" {
			cacheDir = cacheDirPath()
		}
		dsn := args[0]
		if err := fetchTrivyDB(ctx, cacheDir, light, quiet, skipUpdate); err != nil {
			return err
		}

		if err := initDB(ctx, dsn); err != nil {
			return err
		}

		if err := updateDB(ctx, cacheDir, dsn); err != nil {
			return err
		}

		return nil
	},
}

func Execute() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)

	// disable trivy logger
	if err := trivylog.InitLogger(false, true); err != nil {
		rootCmd.PrintErrln(err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&light, "light", "", false, "light")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "", false, "quiet")
	rootCmd.Flags().BoolVarP(&skipUpdate, "skip-update", "", false, "skip updating trivy-db")
	rootCmd.Flags().StringVarP(&cacheDir, "cache-dir", "", "", "cache dir")
}

func fetchTrivyDB(ctx context.Context, cacheDir string, light, quiet, skipUpdate bool) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Fetching trivy-db ... ")
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
		if err := dbClient.Download(ctx, cacheDir, light); err != nil {
			return err
		}
		if err := dbClient.UpdateMetadata(cacheDir); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", "already exist")
	}
	return nil
}

func cacheDirPath() string {
	configDirs := configdir.New("", "trivy-db-to")
	cache := configDirs.QueryCacheFolder()
	return cache.Path
}

func initDB(ctx context.Context, dsn string) error {
	var (
		driver drivers.Driver
		err    error
	)
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Initializing table ... ")
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
		driver, err = mysql.New(db)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported driver '%s'", u.Driver)
	}

	if err := driver.CreateTable(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", "done")
	return nil
}

func updateDB(ctx context.Context, cacheDir, dsn string) error {
	_, _ = fmt.Fprintf(os.Stderr, "%s", "Updating target tables ... \n")
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
		driver, err = mysql.New(db)
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
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", ">> Updating vulnerabilities ... ")
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

		_, _ = fmt.Fprintf(os.Stderr, "%s\n", ">> Update vulnerability_details ... ")
		if err := driver.TruncateVulnDetails(ctx); err != nil {
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
					splited := strings.SplitAfterN(s, " ", 2)
					platform := []byte(splited[0])
					segment := []byte("")
					if len(splited) == 2 {
						segment = []byte(splited[1])
					}
					vulnds = append(vulnds, [][]byte{vID, platform, segment, pkg, v})
				}
				if len(vulnds) > chunkSize {
					if err := driver.InsertVulnDetail(ctx, vulnds); err != nil {
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
