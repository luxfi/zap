package zapmdns_test

import (
	"context"
	"fmt"
	"time"

	zapmdns "github.com/hanzoai/zap-mdns-go"
)

// ExamplePublish — what every Go service in the Hanzo stack does on startup.
func ExamplePublish() {
	pub, err := zapmdns.Publish(zapmdns.PublishOptions{
		Role:         zapmdns.RoleKMS,
		Port:         8443,
		Version:      "0.1.0",
		Proto:        "zap/1",
		Auth:         "iam",
		Capabilities: []string{"sign", "verify", "encrypt", "decrypt"},
	})
	if err != nil {
		panic(err)
	}
	defer pub.Close()
	// service runs forever ...
	_ = pub
}

// ExampleBrowse — find every KMS on the LAN within 2 seconds.
func ExampleBrowse() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	services, err := zapmdns.Browse(ctx, zapmdns.RoleKMS, 2*time.Second)
	if err != nil {
		panic(err)
	}
	for _, s := range services {
		fmt.Printf("%s %s caps=%v\n", s.ServerID, s.URL(), s.Capabilities)
	}
}
