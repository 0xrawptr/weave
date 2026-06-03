package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xrawptr/weave/internal/app"
	"github.com/0xrawptr/weave/internal/config"
	appruntime "github.com/0xrawptr/weave/internal/runtime"

	"go.temporal.io/sdk/client"
	sdkworker "go.temporal.io/sdk/worker"
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

	c, err := client.Dial(client.Options{
		HostPort:  fmt.Sprintf("%s:%d", cfg.Temporal.Host, cfg.Temporal.Port),
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		log.Fatalf("temporal client: %v", err)
	}
	defer c.Close()

	w := sdkworker.New(c, cfg.Temporal.TaskQueue, sdkworker.Options{})
	appruntime.ConfigureWorker(w, runtimeApp)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down worker...")
		w.Stop()
		runtimeApp.Close()
	}()

	log.Printf("worker started on task queue %q", cfg.Temporal.TaskQueue)
	if err := w.Run(sdkworker.InterruptCh()); err != nil {
		log.Fatalf("worker run: %v", err)
	}
}
