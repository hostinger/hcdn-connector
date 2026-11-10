// Command embed runs the connector inside another Go program, with the
// certificate and key in memory and the config built in code.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

func main() { os.Exit(run()) }

func run() int {
	tunnelID := flag.String("tunnel-id", "", "tunnel UUID")
	certFile := flag.String("cert", "cert.pem", "client certificate (PEM)")
	keyFile := flag.String("key", "key.pem", "private key (PEM)")
	bootstrap := flag.String("bootstrap", "tunnel.hostinger.io", "bootstrap endpoints, comma-separated")
	hostname := flag.String("hostname", "", "public host name, for example shop.example.com")
	service := flag.String("url", "http://127.0.0.1:8080", "local service")
	flag.Parse()
	if *tunnelID == "" || *hostname == "" {
		return fail(errors.New("-tunnel-id and -hostname are required"))
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fail(err)
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return fail(err)
	}
	c, err := creds.FromPEM(*tunnelID, certPEM, keyPEM, strings.Split(*bootstrap, ","))
	if err != nil {
		return fail(err)
	}
	store, err := creds.NewMemoryStore(c, nil, nil)
	if err != nil {
		return fail(err)
	}
	cfg := config.Default()
	cfg.TunnelID = *tunnelID
	cfg.AddRule(config.NewIngressRule(*hostname, *service))

	conn, err := connector.New(connector.Options{Config: cfg, Credentials: store, DrainTimeout: 3 * time.Second})
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := conn.Run(ctx); err != nil {
		var ee *connector.ExitError
		if errors.As(err, &ee) {
			return ee.Code
		}
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "embed:", err)
	return 1
}
