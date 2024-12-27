package configuration

import (
	"fmt"
	"net/http"
	"os"

	"github.com/forestnode-io/oneshot/v2/pkg/flags"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type BasicAuth struct {
	Username           string `mapstructure:"username" yaml:"username"`
	Password           string `mapstructure:"password" yaml:"password"`
	PasswordFile       string `mapstructure:"passwordFile" yaml:"passwordFile"`
	PasswordPrompt     bool   `mapstructure:"passwordPrompt" yaml:"passwordPrompt"`
	UnauthorizedPage   string `mapstructure:"unauthorizedPage" yaml:"unauthorizedPage"`
	UnauthorizedStatus int    `mapstructure:"unauthorizedStatus" yaml:"unauthorizedStatus,omitempty"`
	NoDialog           bool   `mapstructure:"noDialog" yaml:"noDialog"`
}

func setBasicAuthFlags(cmd *cobra.Command) {
	fs := pflag.NewFlagSet("Basic Auth Flags", pflag.ExitOnError)
	defer cmd.PersistentFlags().AddFlagSet(fs)

	flags.StringP(fs, "basicauth.username", "username", "u", `Username for basic authentication.
If a password is not also provided then the client may enter any password.`)
	flags.StringP(fs, "basicauth.password", "password", "P", `Password for basic authentication.
If a username is not also provided using the --username flag then the client may enter any username.
If either the --password-prompt or --password-file flags are set, this flag will be ignored.`)
	flags.String(fs, "basicauth.passwordfile", "password-file", `Path to file containing password for basic authentication.
If a username is not also provided then the client may enter any username.
If the --password-prompt flag is set, this flags will be ignored.`)
	flags.BoolP(fs, "basicauth.passwordprompt", "password-prompt", "W", `Prompt for password for basic authentication.
If a username is not also provided then the client may enter any username.
If the --password-file flag is set, this flag will be ignored.`)
	flags.String(fs, "basicauth.unauthorizedpage", "unauthorized-page", `Path to file containing HTML to display when a user is unauthorized.
If this flag is not set then a default page will be displayed.`)
	flags.Int(fs, "basicauth.unauthorizedstatus", "unauthorized-status", `HTTP status code to return when a user is unauthorized.`)
	flags.Bool(fs, "basicauth.nodialog", "no-dialog", `Do not display a dialog box when prompting for credentials.`)

	cobra.AddTemplateFunc("basicAuthFlags", func() *pflag.FlagSet {
		return fs
	})
	cobra.AddTemplateFunc("basicAuthClientFlags", func() *pflag.FlagSet {
		fs := pflag.NewFlagSet("Basic Auth Client Flags", pflag.ExitOnError)
		fs.StringP("username", "u", "", `Username for basic authentication.
If a password is not also provided then the client may enter any password.`)
		fs.StringP("password", "P", "", `Password for basic authentication.
If a username is not also provided using the --username flag then the client may enter any username.
If either the --password-prompt or --password-file flags are set, this flag will be ignored.`)
		fs.String("password-file", "", `Path to file containing password for basic authentication.
If a username is not also provided then the client may enter any username.
If the --password-prompt flag is set, this flags will be ignored.`)
		fs.BoolP("password-prompt", "W", false, `Prompt for password for basic authentication.
If a username is not also provided then the client may enter any username.
If the --password-file flag is set, this flag will be ignored.`)
		return fs
	})
}

func (c *BasicAuth) validate() error {
	if t := http.StatusText(c.UnauthorizedStatus); t == "" {
		return fmt.Errorf("invalid unauthorized status code")
	}

	if c.UnauthorizedPage != "" {
		stat, err := os.Stat(c.UnauthorizedPage)
		if err != nil {
			return fmt.Errorf("unable to stat unauthorized page: %w", err)
		}
		if stat.IsDir() {
			return fmt.Errorf("unauthorized page is a directory")
		}
	}

	return nil
}

func (c *BasicAuth) hydrate() error {
	if c.PasswordFile != "" {
		data, err := os.ReadFile(c.PasswordFile)
		if err != nil {
			return err
		}
		c.Password = string(data)
	}

	return nil
}
