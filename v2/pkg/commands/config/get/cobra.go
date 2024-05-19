package get

import (
	"fmt"
	"os"

	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func New(config *configuration.Root) *Cmd {
	return &Cmd{
		config: config,
	}
}

type Cmd struct {
	cobraCommand *cobra.Command
	config       *configuration.Root
}

func (c *Cmd) Cobra() *cobra.Command {
	if c.cobraCommand != nil {
		return c.cobraCommand
	}

	c.cobraCommand = &cobra.Command{
		Use:   "get path",
		Short: "Get an individual value from a oneshot configuration file.",
		Long:  "Get an individual value from a oneshot configuration file.",
		RunE:  c.run,
		Args:  cobra.MaximumNArgs(1),
	}

	c.cobraCommand.SetUsageTemplate(usageTemplate)

	return c.cobraCommand
}

func (c *Cmd) run(cmd *cobra.Command, args []string) error {
	m := map[string]any{}
	err := viper.Unmarshal(&m)
	if err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	dc, ok := m["discovery"].(map[string]any)
	if !ok {
		return fmt.Errorf("failed to get discovery configuration")
	}

	key, ok := dc["key"].(string)
	if !ok {
		return fmt.Errorf("failed to get discovery key")
	}

	if key != "" {
		if 8 < len(key) {
			key = key[:8] + "..."
		} else {
			key = "********"
		}
		viper.Set("discovery.key", key)
	}
	dc["key"] = key
	m["discovery"] = dc

	v := viper.New()
	v.MergeConfigMap(m)

	if len(args) == 0 || args[0] == "" {
		return yaml.NewEncoder(os.Stdout).Encode(v.AllSettings())
	}

	configData := v.Get(args[0])
	if configData == nil {
		return output.UsageErrorF("no such key: %s", args[0])
	}

	return yaml.NewEncoder(os.Stdout).Encode(configData)
}
