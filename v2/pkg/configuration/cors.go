package configuration

import (
	"fmt"
	"net/http"

	"github.com/forestnode-io/oneshot/v2/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type CORS struct {
	AllowedOrigins      []string `mapstructure:"allowedOrigins" yaml:"allowedOrigins"`
	AllowedHeaders      []string `mapstructure:"allowedHeaders" yaml:"allowedHeaders"`
	MaxAge              int      `mapstructure:"maxAge" yaml:"maxAge"`
	AllowCredentials    bool     `mapstructure:"allowCredentials" yaml:"allowCredentials"`
	AllowPrivateNetwork bool     `mapstructure:"allowPrivateNetwork" yaml:"allowPrivateNetwork"`
	SuccessStatus       int      `mapstructure:"successStatus" yaml:"successStatus,omitempty"`
}

func setCORSFlags(cmd *cobra.Command) {
	fs := pflag.NewFlagSet("CORS Flags", pflag.ExitOnError)
	defer cmd.PersistentFlags().AddFlagSet(fs)

	flags.StringSlice(fs, "cors.allowedorigins", "cors-allowed-origins", `Comma separated list of allowed origins.
An allowed origin may be a domain name, or a wildcard (*).
A domain name may contain a wildcard (*).`)
	flags.StringSlice(fs, "cors.allowedheaders", "cors-allowed-headers", `Comma separated list of allowed headers.
An allowed header may be a header name, or a wildcard (*).
If a wildcard (*) is used, all headers will be allowed.`)
	flags.Int(fs, "cors.maxage", "cors-max-age", "How long the preflight results can be cached by the client.")
	flags.Bool(fs, "cors.allowcredentials", "cors-allow-credentials", `Allow credentials like cookies, basic auth headers, and ssl certs for CORS requests.`)
	flags.Bool(fs, "cors.allowprivatenetwork", "cors-allow-private-network", `Allow private network requests from CORS requests.`)
	flags.Int(fs, "cors.successstatus", "cors-success-status", `HTTP status code to return for successful CORS requests.`)

	cobra.AddTemplateFunc("corsFlags", func() *pflag.FlagSet {
		return fs
	})
}

func (c *CORS) validate() error {
	if t := http.StatusText(c.SuccessStatus); t == "" {
		return fmt.Errorf("invalid success status code")
	}
	return nil
}
