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

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/indicator"
	"github.com/k1LoW/trivy-db-to-db/version"
	"github.com/shibukawa/configdir"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"k8s.io/utils/clock"
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "fetch trivy-db from GitHub repo releases",
	Long:  `fetch trivy-db from GitHub repo releases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		if cacheDir == "" {
			cacheDir = cacheDirPath()
		}
		return fetchTrivyDB(ctx, cacheDir, light, quiet, skipUpdate)
	},
}

func init() {
	rootCmd.AddCommand(fetchCmd)
	fetchCmd.Flags().BoolVarP(&light, "light", "", false, "light")
	fetchCmd.Flags().BoolVarP(&quiet, "quiet", "", false, "quiet")
	fetchCmd.Flags().BoolVarP(&skipUpdate, "skip-update", "", false, "skip updating trivy-db")
	fetchCmd.Flags().StringVarP(&cacheDir, "cache-dir", "", "", "cache dir")
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
	configDirs := configdir.New("", "trivy-db-to-db")
	cache := configDirs.QueryCacheFolder()
	return cache.Path
}
