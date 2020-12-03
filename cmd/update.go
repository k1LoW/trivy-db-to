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
	"path/filepath"
	"strings"
	"time"

	"github.com/k1LoW/trivy-db-to-db/drivers"
	"github.com/k1LoW/trivy-db-to-db/drivers/mysql"
	"github.com/spf13/cobra"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
)

const chunkSize = 100

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update",
	Long:  `update.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			driver drivers.Driver
			err    error
		)
		ctx := context.Background()
		if cacheDir == "" {
			cacheDir = cacheDirPath()
		}

		if err := fetchTrivyDB(ctx, cacheDir, light, quiet, skipUpdate); err != nil {
			return err
		}

		dsn := args[0]
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
			if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
				ss := string(source)
				if ss == "trivy" || ss == "vulnerability" {
					return nil
				}
				cmd.PrintErrln(ss)
				c := b.Cursor()
				vulnds := [][][]byte{}
				for pkg, _ := c.First(); pkg != nil; pkg, _ = c.Next() {
					cb := b.Bucket(pkg)
					cbc := cb.Cursor()
					for vID, v := cbc.First(); vID != nil; vID, v = cbc.Next() {
						splited := strings.SplitAfterN(ss, " ", 2)
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

		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVarP(&light, "light", "", false, "light")
	updateCmd.Flags().BoolVarP(&quiet, "quiet", "", false, "quiet")
	updateCmd.Flags().BoolVarP(&skipUpdate, "skip-update", "", false, "skip updating trivy-db")
	updateCmd.Flags().StringVarP(&cacheDir, "cache-dir", "", "", "cache dir")
}
