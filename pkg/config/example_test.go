package config_test

import (
	"fmt"

	"github.com/hostinger/hcdn-connector/pkg/config"
)

func ExampleDefault() {
	cfg := config.Default()
	cfg.TunnelID = "3f9c2a7e-0b3e-4d0a-9d0a-1c8f5e7b2a11"
	cfg.AddRule(config.NewIngressRule("shop.example.com", "http://127.0.0.1:8080"))
	cfg.HomePops = 1
	if err := cfg.Validate(); err != nil {
		fmt.Println(err)
		return
	}
	for _, r := range cfg.Ingress {
		fmt.Printf("%q -> %s\n", r.Hostname, r.Service)
	}
	// Output:
	// "shop.example.com" -> http://127.0.0.1:8080
	// "" -> http_status:404
}
