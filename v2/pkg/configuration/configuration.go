package configuration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "embed"

	"github.com/miracl/conflate"
	"github.com/oneshot-uno/oneshot/v2/pkg/log"
	"github.com/oneshot-uno/oneshot/v2/pkg/sys"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var (
	//go:embed config.yaml
	defaultConfig []byte
)

var (
	ConfigPath    string
	userConfigDir string
)

func init() {
	if err := setUserConfig(); err != nil {
		panic(err)
	}
	if err := ensureConfigDir(); err != nil {
		panic(err)
	}
	if err := ensureConfigFile(); err != nil {
		panic(err)
	}
	if defaultConfig == nil {
		panic("defaultConfig is nil")
	}
}

func setUserConfig() error {
	if confPath := os.Getenv("ONESHOT_CONFIG"); confPath != "" {
		userConfigDir = filepath.Dir(confPath)
		ConfigPath = confPath
		return nil
	}

	// Try to use the user config dir from the OS
	ucd, err := os.UserConfigDir()
	if err == nil {
		userConfigDir = filepath.Join(ucd, "oneshot")
		ConfigPath = filepath.Join(ucd, "oneshot", "config.yaml")
	} else if errors.Is(err, os.ErrNotExist) {
		userConfigDir = ""
		ConfigPath = ""
		// if on unix, try /etc/oneshot/config.yaml
		if sys.RunningOnUNIX() {
			if _, err := os.Stat("/etc/oneshot"); err == nil {
				ConfigPath = "/etc/oneshot/config.yaml"
				userConfigDir = "/etc/oneshot"
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("failed to stat /etc/oneshot: %w", err)
			}
		}
	} else {
		return fmt.Errorf("failed to get user config dir: %w", err)
	}

	return nil
}

func ensureConfigDir() error {
	if ConfigPath == "" {
		return nil
	}

	_, err := os.Stat(userConfigDir)
	if errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir(userConfigDir, 0700); err != nil {
			return fmt.Errorf("failed to create user config dir: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat user config dir: %w", err)
	}

	return nil
}

func ensureConfigFile() error {
	if ConfigPath == "" {
		return nil
	}

	_, err := os.Stat(ConfigPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat user config file: %w", err)
	}

	file, err := os.Create(ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create user config file: %w", err)
	}
	defer file.Close()

	if _, err = file.Write(defaultConfig); err != nil {
		return fmt.Errorf("failed to write default config to user config file: %w", err)
	}

	return nil
}

type Configuration interface {
	Init()
	SetFlags(*cobra.Command, *viper.Viper)
	MergeFlags()
	Validate() error
}

func ReadConfig() (*Root, error) {
	var (
		config Root
		log    = log.Logger()

		data []byte
		err  error
	)
	if ConfigPath == "" {
		data = defaultConfig
		log.Info().Msg("using built-in default config")
	} else {
		data, err = os.ReadFile(ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read user config file: %w", err)
		}
	}

	backgroundConfig, err := conflate.FromData(defaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create background config: %w", err)
	}

	if err = backgroundConfig.AddData(data); err != nil {
		return nil, fmt.Errorf("failed to add user config data to background config %w", err)
	}

	confData, err := backgroundConfig.MarshalYAML()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal background config: %w", err)
	}

	if err = yaml.Unmarshal(confData, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal background config: %w", err)
	}

	return &config, nil
}
