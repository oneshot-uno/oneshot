package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"net/http"

	"github.com/spf13/viper"
)

var (
	configPath string
)

func init() {
	setConfigPath()
	setEnv()
	setDefault()
	softEnsureConfigFile()
	readInConfig()
}

func ConfigPath() string {
	return configPath
}

func setConfigPath() {
	if x := os.Getenv("ONESHOT_CONFIG"); x != "" {
		configPath = os.Getenv("ONESHOT_CONFIG")
		viper.SetConfigFile(configPath)
		return
	}

	configDir, err := os.UserConfigDir()
	if err == nil {
		configPath = configDir + "/oneshot/config.yaml"
		viper.SetConfigFile(configPath)
	}
}

func softEnsureConfigFile() {
	_, err := os.Stat(configPath)
	if !os.IsNotExist(err) {
		return
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	file, err := os.Create(configPath)
	if err != nil {
		return
	}
	defer file.Close()

	viper.WriteConfig()
}

func setEnv() {
	viper.SetEnvPrefix("ONESHOT")
	viper.SetEnvKeyReplacer(
		strings.NewReplacer(".", "_"),
	)
	viper.AutomaticEnv()
}

func setDefault() {
	viper.SetTypeByDefaultValue(true)

	// output
	viper.SetDefault("output.quiet", false)
	viper.SetDefault("output.format", "")
	viper.SetDefault("output.qrCode", false)
	viper.SetDefault("output.noColor", false)

	// server
	viper.SetDefault("server.host", "")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.timeout", 0*time.Second)
	viper.SetDefault("server.allowbots", false)
	viper.SetDefault("server.maxreadsize", "0")
	viper.SetDefault("server.exitonfail", "0")
	viper.SetDefault("server.tlscert", "")
	viper.SetDefault("server.tlskey", "")

	// basic auth
	viper.SetDefault("basicauth.username", "")
	viper.SetDefault("basicauth.password", "")
	viper.SetDefault("basicauth.passwordfile", "")
	viper.SetDefault("basicauth.passwordprompt", false)
	viper.SetDefault("basicauth.unauthorizedpage", "")
	viper.SetDefault("basicauth.unauthorizedstatus", http.StatusUnauthorized)
	viper.SetDefault("basicauth.noDialog", false)

	// cors
	viper.SetDefault("cors.allowedorigins", []string{})
	viper.SetDefault("cors.allowedheaders", []string{})
	viper.SetDefault("cors.maxage", 0)
	viper.SetDefault("cors.allowcredentials", false)
	viper.SetDefault("cors.allowprivatenetwork", false)
	viper.SetDefault("cors.successstatus", http.StatusNoContent)

	// nat traversal - p2p
	viper.SetDefault("nattraversal.p2p.enabled", false)
	viper.SetDefault("nattraversal.p2p.only", false)
	viper.SetDefault("nattraversal.p2p.discoverydir", "")
	viper.SetDefault("nattraversal.p2p.webrtcconfiguration", []byte{})
	viper.SetDefault("nattraversal.p2p.webrtcconfigurationfile", "")
	viper.SetDefault("nattraversal.p2p.icegathertimeout", 30*time.Second)

	// nat traversal - upnp
	viper.SetDefault("nattraversal.upnp.enabled", false)
	viper.SetDefault("nattraversal.upnp.externalport", 0)
	viper.SetDefault("nattraversal.upnp.duration", 0*time.Second)
	viper.SetDefault("nattraversal.upnp.timeout", 60*time.Second)

	// subcommands - receive
	viper.SetDefault("cmd.receive.csrftoken", "")
	viper.SetDefault("cmd.receive.eol", "")
	viper.SetDefault("cmd.receive.uifile", "")
	viper.SetDefault("cmd.receive.decodeb64", false)
	viper.SetDefault("cmd.receive.status", http.StatusOK)
	viper.SetDefault("cmd.receive.header", map[string][]string{})
	viper.SetDefault("cmd.receive.includebody", false)

	// cmd - send
	archiveMethod := "tar.gz"
	if runtime.GOOS == "windows" {
		archiveMethod = "zip"
	}
	viper.SetDefault("cmd.send.archivemethod", archiveMethod)
	viper.SetDefault("cmd.send.nodownload", false)
	viper.SetDefault("cmd.send.mime", "")
	viper.SetDefault("cmd.send.name", "")
	viper.SetDefault("cmd.send.statuscode", http.StatusOK)
	viper.SetDefault("cmd.send.header", map[string][]string{})

	// cmd - exec
	viper.SetDefault("cmd.exec.enforcecgi", false)
	viper.SetDefault("cmd.exec.env", []string{})
	viper.SetDefault("cmd.exec.dir", "")
	viper.SetDefault("cmd.exec.stderr", "")
	viper.SetDefault("cmd.exec.replaceheaders", false)
	viper.SetDefault("cmd.exec.headers", map[string][]string{})

	// cmd - redirect
	viper.SetDefault("cmd.redirect.status", http.StatusTemporaryRedirect)
	viper.SetDefault("cmd.redirect.header", map[string][]string{})

	// cmd - rproxy
	viper.SetDefault("cmd.rproxy.status", 0)
	viper.SetDefault("cmd.rproxy.method", "")
	viper.SetDefault("cmd.rproxy.matchhost", false)
	viper.SetDefault("cmd.rproxy.tee", false)
	viper.SetDefault("cmd.rproxy.spoofhost", "")
	viper.SetDefault("cmd.rproxy.requestheader", map[string][]string{})
	viper.SetDefault("cmd.rproxy.responseheader", map[string][]string{})

	// cmd - p2p - browserclient
	viper.SetDefault("cmd.p2p.browserclient.open", false)

	// cmd - p2p - client - receive

	// cmd - p2p - client - send
	viper.SetDefault("cmd.p2p.client.send.name", "")
	viper.SetDefault("cmd.p2p.client.send.archivemethod", "")

	// cmd - discovery server
	viper.SetDefault("cmd.discoveryserver.requiredkey.path", "")
	viper.SetDefault("cmd.discoveryserver.requiredkey.value", "")
	viper.SetDefault("cmd.discoveryserver.jwt.key", "")
	viper.SetDefault("cmd.discoveryserver.jwt.value", "")
	viper.SetDefault("cmd.discoveryserver.maxqueuesize", 0)
	viper.SetDefault("cmd.discoveryserver.urlassignment.scheme", "")
	viper.SetDefault("cmd.discoveryserver.urlassignment.domain", "")
	viper.SetDefault("cmd.discoveryserver.urlassignment.port", "")
	viper.SetDefault("cmd.discoveryserver.urlassignment.path", "")
	viper.SetDefault("cmd.discoveryserver.urlassignment.pathprefix", "")
	viper.SetDefault("cmd.discoveryserver.server.addr", "")
	viper.SetDefault("cmd.discoveryserver.server.tlscert", "")
	viper.SetDefault("cmd.discoveryserver.server.tlskey", "")

	// discovery
	viper.SetDefault("discovery.enabled", true)
	viper.SetDefault("discovery.addr", "")
	viper.SetDefault("discovery.key", "")
	viper.SetDefault("discovery.keypath", "")
	viper.SetDefault("discovery.insecure", false)
	viper.SetDefault("discovery.preferredurl", "")
	viper.SetDefault("discovery.requiredurl", "")
	viper.SetDefault("discovery.onlyredirect", false)
	viper.SetDefault("discovery.reports.enabled", true)
	viper.SetDefault("discovery.reports.headerfilter.usedefaults", true)
	viper.SetDefault("discovery.reports.headerfilter.allow", []string{})
	viper.SetDefault("discovery.reports.headerfilter.block", []string{})
}

func readInConfig() {
	if configPath == "" {
		return
	}
	viper.ReadInConfig()
}
