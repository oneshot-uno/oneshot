package configuration

import (
	"fmt"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Server struct {
	Host        string        `mapstructure:"host" yaml:"host"`
	Port        int           `mapstructure:"port" yaml:"port"`
	Timeout     time.Duration `mapstructure:"timeout" yaml:"timeout"`
	AllowBots   bool          `mapstructure:"allowBots" yaml:"allowBots"`
	MaxReadSize string        `mapstructure:"maxReadSize" yaml:"maxReadSize"`
	ExitOnFail  bool          `mapstructure:"exitOnFail" yaml:"exitOnFail"`
	TLS         *TLS          `mapstructure:"tls" yaml:"tls"`
}

func (c *Server) IsUsingTLS() bool {
	if c.TLS == nil {
		return false
	}
	return c.TLS.IsEnabled()
}

func setServerFlags(cmd *cobra.Command) {
	fs := pflag.NewFlagSet("Server Flags", pflag.ExitOnError)
	defer cmd.PersistentFlags().AddFlagSet(fs)

	flags.String(fs, "server.host", "host", "Host to listen on")
	flags.IntP(fs, "server.port", "port", "p", "Port to listen on")
	flags.Duration(fs, "server.timeout", "timeout", `How long to wait for a connection to be established before timing out.
A value of 0 will cause oneshot to wait indefinitely.`)
	flags.Bool(fs, "server.allowbots", "allow-bots", "Allow bots access")
	flags.String(fs, "server.maxreadsize", "max-read-size", `Maximum read size for incoming request bodies. A value of zero will cause oneshot to read until EOF.
	Format is a number followed by a unit of measurement.
	Valid units are: b, B,
		Kb, KB, KiB,
		Mb, MB, MiB,
		Gb, GB, GiB,
		Tb, TB, TiB
	Example: 1.5GB`)
	flags.Bool(fs, "server.exitonfail", "exit-on-fail", "Exit after a failed transfer, without waiting for a new connection")
	flags.String(fs, "server.tlscert", "tls-cert", "Path to TLS certificate")
	flags.String(fs, "server.tlskey", "tls-key", "Path to TLS key")

	cobra.AddTemplateFunc("serverFlags", func() *pflag.FlagSet {
		return fs
	})
}

func (c *Server) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	return nil
}
