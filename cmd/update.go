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
	"time"

	"github.com/k1LoW/trivy-db-to-db/drivers"
	"github.com/k1LoW/trivy-db-to-db/drivers/mysql"
	"github.com/spf13/cobra"
	"github.com/xo/dburl"
	bolt "go.etcd.io/bbolt"
)

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
		cmd.PrintErrln("Fetch trivy-db...")
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
			if err := b.ForEach(func(vID, v []byte) error {
				return driver.InsertVuln(vID, v)
			}); err != nil {
				return err
			}

			if err := tx.ForEach(func(source []byte, b *bolt.Bucket) error {
				ss := string(source)
				if ss == "trivy" || ss == "vulnerability" {
					return nil
				}
				cmd.PrintErrln(ss)
				return b.ForEach(func(pkg, _ []byte) error {
					cb := b.Bucket(pkg)
					return cb.ForEach(func(vID, v []byte) error {
						return driver.InsertVulnDetail(vID, source, pkg, v)
					})
				})
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
