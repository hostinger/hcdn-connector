package connector_test

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/hostinger/hcdn-connector/pkg/config"
	"github.com/hostinger/hcdn-connector/pkg/connector"
	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// Expose http://127.0.0.1:8080 as shop.example.com with credentials held in memory.
func Example() {
	const tunnelID = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"
	certPEM, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}
	c, err := creds.FromPEM(tunnelID, certPEM, keyPEM, []string{"fra.tunnel.hostinger.io"})
	if err != nil {
		log.Fatal(err)
	}
	store, err := creds.NewMemoryStore(c, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	cfg := config.Default()
	cfg.TunnelID = tunnelID
	cfg.AddRule(config.NewIngressRule("shop.example.com", "http://127.0.0.1:8080"))

	conn, err := connector.New(connector.Options{Config: cfg, Credentials: store, DrainTimeout: 3 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := conn.Run(ctx); err != nil {
		var ee *connector.ExitError
		if errors.As(err, &ee) {
			log.Printf("tunnel stopped by the edge (exit %d)", ee.Code)
			return
		}
		log.Fatal(err)
	}
}

// Expose http://localhost:5173 on a random quick tunnel URL until Ctrl-C or expiry.
func ExampleRunQuick() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	expired, err := connector.RunQuick(ctx, connector.QuickOptions{
		URL:        "http://localhost:5173",
		HostHeader: "localhost",
		Version:    "example/1.0.0",
		OnReady: func(q connector.QuickTunnel) {
			log.Printf("%s until %s", q.URL, q.ExpiresAt.Format(time.RFC3339))
		},
		OnPause: func(p connector.QuickPause) {
			log.Printf("paused (%s) until %s", p.Reason, p.RetryAt.Format(time.TimeOnly))
		},
	})
	switch {
	case errors.Is(err, connector.ErrEdgeUnreachable):
		log.Fatal("outbound TCP 7844 is blocked")
	case errors.Is(err, connector.ErrOwnerRequired):
		log.Fatal("sign in first")
	case err != nil:
		log.Fatal(err)
	case expired:
		log.Print("tunnel expired")
	}
}
