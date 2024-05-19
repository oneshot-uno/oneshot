package configuration

import (
	"fmt"
	"net/http"
	"os"

	"github.com/forestnode-io/oneshot/v2/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Configuration struct {
	CSRFToken      string `mapstructure:"csrftoken" yaml:"csrftoken"`
	EOL            string `mapstructure:"eol" yaml:"eol"`
	UI             string `mapstructure:"uifile" yaml:"uifile"`
	DecodeBase64   bool   `mapstructure:"decodeb64" yaml:"decodeb64"`
	StatusCode     int    `mapstructure:"status" yaml:"status"`
	IncludeBody    bool   `mapstructure:"includebody" yaml:"includebody"`
	StreamToStdout bool   `mapstructure:"stream" yaml:"stream"`
}

func (c *Configuration) Validate() error {
	if (c.EOL != "unix" && c.EOL != "dos") && c.EOL != "" {
		return fmt.Errorf("invalid eol: %s", c.EOL)
	}

	if c.UI != "" {
		stat, err := os.Stat(c.UI)
		if err != nil {
			return fmt.Errorf("invalid ui file: %w", err)
		}
		if stat.IsDir() {
			return fmt.Errorf("invalid ui file: %s is a directory", c.UI)
		}
	}

	if t := http.StatusText(c.StatusCode); t == "" {
		return fmt.Errorf("invalid status code: %d", c.StatusCode)
	}

	return nil
}

func (c *Configuration) Hydrate() error {
	return nil
}

func SetFlags(cmd *cobra.Command) {
	fs := pflag.NewFlagSet("receive flags", pflag.ExitOnError)
	defer cmd.Flags().AddFlagSet(fs)

	flags.String(fs, "cmd.receive.csrftoken", "csrf-token", "Use a CSRF token, if left empty, a random token will be generated.")
	flags.String(fs, "cmd.receive.eol", "eol", `How to parse EOLs in the received file.
Acceptable values are 'unix' and 'dos'; 'unix': '\n', 'dos': '\r\n'.`)
	flags.StringP(fs, "cmd.receive.uifile", "ui", "U", "Name of ui file to use.")
	flags.Bool(fs, "cmd.receive.decodeb64", "decode-b64", "Decode base-64.")
	flags.Int(fs, "cmd.receive.status", "status-code", "HTTP status code sent to client.")
	flags.Bool(fs, "cmd.receive.includebody", "include-body", "Include the request body in the report. If not using json output, this will be ignored.")
	flags.Bool(fs, "cmd.receive.stream", "stream", `Stream request body without buffering.
Contents of failed transfer attempts will be included.
Only applied when receiving to stdout.`)

	cobra.AddTemplateFunc("receiveFlags", func() *pflag.FlagSet {
		return fs
	})
}
