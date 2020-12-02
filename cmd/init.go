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
	"fmt"

	"github.com/k1LoW/trivy-db-to-db/drivers"
	"github.com/k1LoW/trivy-db-to-db/drivers/mysql"
	"github.com/spf13/cobra"
	"github.com/xo/dburl"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "init",
	Long:  `init.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var (
			driver drivers.Driver
			err    error
		)
		cmd.PrintErrln("Initialize table...")
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

		return driver.CreateTable()
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
