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
	"os"

	trivylog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/k1LoW/trivy-db-to/internal"
	"github.com/k1LoW/trivy-db-to/version"
	"github.com/shibukawa/configdir"
	"github.com/spf13/cobra"
)

var (
	quiet      bool
	light      bool
	skipInit   bool
	skipUpdate bool
	cacheDir   string
	vulnerabilitiesTableName   string
	adivisoryTableName   string
)

var rootCmd = &cobra.Command{
	Use:          "trivy-db-to [DSN]",
	Short:        "trivy-db-to is a tool for migrating/converting vulnerability information from Trivy DB to other datasource",
	Long:         `trivy-db-to is a tool for migrating/converting vulnerability information from Trivy DB to other datasource.`,
	SilenceUsage: true,
	Version:      version.Version,
	Args:         cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		if cacheDir == "" {
			cacheDir = cacheDirPath()
		}
		dsn := args[0]
		if err := internal.FetchTrivyDB(ctx, cacheDir, light, quiet, skipUpdate); err != nil {
			return err
		}

		if !skipInit {
			if err := internal.InitDB(ctx, dsn, vulnerabilitiesTableName, adivisoryTableName); err != nil {
				return err
			}
		}

		if err := internal.UpdateDB(ctx, cacheDir, dsn, vulnerabilitiesTableName, adivisoryTableName); err != nil {
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
	// rootCmd.Flags().BoolVarP(&quiet, "quiet", "", false, "quiet")
	quiet = false
	rootCmd.Flags().BoolVarP(&skipInit, "skip-init-db", "", false, "skip initializing target datasource")
	rootCmd.Flags().BoolVarP(&skipUpdate, "skip-update", "", false, "skip updating Trivy DB")
	rootCmd.Flags().StringVarP(&cacheDir, "cache-dir", "", "", "cache dir")
	rootCmd.Flags().StringVarP(&vulnerabilitiesTableName, "vulnerabilities-table-name", "", "vulnerabilities", "Vulnerabilities Table Name")
	rootCmd.Flags().StringVarP(&adivisoryTableName, "advisory-table-name", "", "vulnerability_advisories", "Vulnerability Advisories Table Name")
}

func cacheDirPath() string {
	configDirs := configdir.New("", "trivy-db-to")
	cache := configDirs.QueryCacheFolder()
	return cache.Path
}
