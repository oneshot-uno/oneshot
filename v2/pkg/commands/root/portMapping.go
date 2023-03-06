package root

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/raphaelreyna/oneshot/v2/pkg/events"
	upnpigd "github.com/raphaelreyna/oneshot/v2/pkg/net/upnp-igd"
	"github.com/raphaelreyna/oneshot/v2/pkg/output"
	"github.com/spf13/pflag"
)

func (r *rootCommand) handlePortMap(ctx context.Context, flags *pflag.FlagSet) (func(), error) {
	var (
		externalPort, _        = flags.GetInt("external-port")
		portMappingDuration, _ = flags.GetDuration("port-mapping-duration")
		mapPort, _             = flags.GetBool("map-port")

		cancel = func() {}
	)

	userSetUPnPFlag := flags.Lookup("external-port").Changed || flags.Lookup("port-mapping-duration").Changed

	if !mapPort && !userSetUPnPFlag {
		return cancel, nil
	}

	portString, _ := flags.GetString("port")
	portString = strings.TrimPrefix(portString, ":")
	port, err := strconv.Atoi(portString)
	if err != nil {
		return cancel, fmt.Errorf("failed to parse port: %w", err)
	}

	finishSpinning := output.DisplaySpinner(ctx,
		333*time.Millisecond,
		"negotiating port mapping",
		"negotiating port mapping ... done",
		[]string{".", "..", "...", ".."},
	)

	discoveryTimeout, _ := flags.GetDuration("upnp-discovery-timeout")
	devChan, err := upnpigd.Discover("oneshot", discoveryTimeout, http.DefaultClient)
	if err != nil {
		return cancel, fmt.Errorf("failed to discover UPnP IGD: %w", err)
	}

	devs := make([]*upnpigd.Device, 0)
	for dev := range devChan {
		devs = append(devs, dev)
	}

	if len(devs) == 0 {
		return cancel, errors.New("no UPnP IGD devices found")
	}

	dev := devs[0]
	if err := dev.AddPortMapping(ctx, "TCP", externalPort, port, "oneshot", portMappingDuration); err != nil {
		finishSpinning()
		return cancel, fmt.Errorf("failed to add port mapping: %w", err)
	}
	log.Printf("added port mapping for %d -> %d", port, externalPort)

	log.Println("getting external IP ...")
	r.externalIP, err = dev.GetExternalIP(ctx)
	if err != nil {
		finishSpinning()
		return cancel, fmt.Errorf("failed to get external IP: %w", err)
	}
	log.Printf("... external IP: %s", r.externalIP)

	finishSpinning()

	t := time.AfterFunc(portMappingDuration, func() {
		events.Stop(ctx)
	})

	return func() {
		t.Stop()
		if err := dev.DeletePortMapping(ctx, "TCP", externalPort); err != nil {
			log.Printf("failed to delete port mapping: %v", err)
		}
		log.Printf("deleted port mapping for %d -> %d", port, externalPort)
	}, nil
}
