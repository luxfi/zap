// Command echoserver runs a zapweb (ZAP-over-WebSocket) echo service for
// cross-language integration testing. It registers test.echo (prefixes
// its text@0 argument with "echo:") and serves it at /zap, so the
// TypeScript client in zapweb/ts can prove the browser path is wire-
// compatible end to end.
//
//	go run ./zapweb/cmd/echoserver   # serves :8089/zap
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	zap "github.com/luxfi/zap"
	"github.com/luxfi/zap/zapclient"
	"github.com/luxfi/zap/zapweb"
)

func main() {
	addr := ":8089"
	if v := os.Getenv("ECHO_ADDR"); v != "" {
		addr = v
	}
	srv, err := zapclient.NewServer("_lux-echo._tcp",
		zapclient.WithNoDiscovery(),
		zapclient.WithServerPort(0),
	)
	if err != nil {
		log.Fatalf("echoserver: %v", err)
	}
	if err := srv.Register("test.echo", func(ctx context.Context, peer zapclient.PeerInfo, req *zap.Message) (*zap.Message, error) {
		in := req.Root().Text(0)
		b := zap.NewBuilder(256)
		ob := b.StartObject(64)
		ob.SetText(0, "echo:"+in)
		ob.FinishAsRoot()
		out, _ := zap.Parse(b.Finish())
		return out, nil
	}); err != nil {
		log.Fatalf("echoserver register: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/zap", zapweb.Handler(srv, zapweb.Options{OriginPatterns: []string{"*"}}))
	log.Printf("zapweb echo serving %s/zap", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("echoserver listen: %v", err)
	}
}
