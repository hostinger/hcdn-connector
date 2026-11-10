package creds_test

import (
	"context"
	"log"
	"os"

	"github.com/hostinger/hcdn-connector/pkg/creds"
)

// A memory store with a refresh function: an unknown_serial goaway from the
// edge fetches new credentials instead of stopping the connector.
func ExampleNewMemoryStore() {
	const tunnelID = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"
	bootstrap := []string{"fra.tunnel.hostinger.io"}
	load := func() (*creds.Credentials, error) {
		certPEM, err := os.ReadFile("cert.pem")
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile("key.pem")
		if err != nil {
			return nil, err
		}
		return creds.FromPEM(tunnelID, certPEM, keyPEM, bootstrap)
	}
	c, err := load()
	if err != nil {
		log.Fatal(err)
	}
	store, err := creds.NewMemoryStore(c, nil, func(context.Context) (*creds.Credentials, error) { return load() })
	if err != nil {
		log.Fatal(err)
	}
	store.SetExpiryHint("run the enrollment again")
	log.Println("serial", store.Current().Serial)
}
