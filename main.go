package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xrawptr/weave/internal/api"
	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/config"

	"go.temporal.io/sdk/client"
)

func main() {
	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()

	runtimeApp, err := app.New(ctx, cfg)
	if err != nil {
		log.Fatalf("artifact init: %v", err)
	}
	log.Printf("registered %d artifacts", len(runtimeApp.Registry.List()))

	temporalClient, err := client.Dial(client.Options{
		HostPort:  cfg.Temporal.Host + ":" + formatPort(cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Printf("WARNING: Temporal unavailable: %v (workflow execution disabled)", err)
	}

	server := api.NewServer(cfg, runtimeApp.Registry, runtimeApp.Repo, temporalClient)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		server.Shutdown(ctx)
		runtimeApp.Close()
		if temporalClient != nil {
			temporalClient.Close()
		}
	}()

	log.Println("weave server starting...")
	if err := server.Run(); err != nil {
		log.Fatalf("server run: %v", err)
	}
}

func formatPort(port int) string {
	return fmt.Sprintf("%d", port)
}
