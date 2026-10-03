// Command filehouse runs the Nekostick object storage microservice.
//
// Subcommands: run (default), status, doctor, register-permissions. Flags are
// documented by -h; every value can also come from a FILEHOUSE_* environment
// variable.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/crazy4chicken/nsc-filehouse/internal/blob"
	"github.com/crazy4chicken/nsc-filehouse/internal/config"
	"github.com/crazy4chicken/nsc-filehouse/internal/gc"
	"github.com/crazy4chicken/nsc-filehouse/internal/httpapi"
	"github.com/crazy4chicken/nsc-filehouse/internal/iamauth"
	"github.com/crazy4chicken/nsc-filehouse/internal/presign"
	"github.com/crazy4chicken/nsc-filehouse/internal/store"
)

// version is set at build time with -ldflags "-X main.version=<version>".
var version = "dev"

const (
	serviceName     = "filehouse"
	shutdownTimeout = 10 * time.Second
	doctorTimeout   = 30 * time.Second
	registerTimeout = 60 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	for _, arg := range args {
		if arg == "-version" || arg == "--version" {
			fmt.Println(version)
			return 0
		}
	}
	command := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}

	cfg, warnings, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		return 2
	}
	flags := flag.NewFlagSet(serviceName+" "+command, flag.ExitOnError)
	config.BindFlags(flags, cfg)
	adminToken := ""
	if command == "register-permissions" {
		flags.StringVar(&adminToken, "token", os.Getenv(config.EnvTeamusersAdminToken), "teamusers admin token")
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}

	logger, err := newLogger(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		return 2
	}
	for _, warning := range warnings {
		logger.Warn("configuration warning", "warning", warning)
	}

	switch command {
	case "run":
		return runServer(cfg, logger)
	case "status":
		return runStatus(cfg)
	case "doctor":
		return runDoctor(cfg, logger)
	case "register-permissions":
		return runRegisterPermissions(cfg, logger, adminToken)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", command)
		flags.Usage()
		return 2
	}
}

// runServer serves traffic until SIGINT or SIGTERM arrives.
func runServer(cfg *config.Config, log *slog.Logger) int {
	if err := cfg.Validate(); err != nil {
		log.Error("invalid configuration", "error", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.ConnectionString, log)
	if err != nil {
		log.Error("open database", "error", err)
		return 1
	}
	defer db.Close()
	if _, err := db.Migrate(ctx); err != nil {
		log.Error("apply migrations", "error", err)
		return 1
	}

	blobs, err := blob.Open(cfg.BlobDir)
	if err != nil {
		log.Error("open blob store", "error", err)
		return 1
	}

	options := iamauthOptions(cfg, log)
	for _, warning := range options.Warnings() {
		log.Warn("iam configuration warning", "warning", warning)
	}
	authorizer, err := iamauth.NewAuthorizer(options)
	if err != nil {
		log.Error("init iam authorizer", "error", err)
		return 1
	}
	defer authorizer.Close()

	signer, err := presign.Load(cfg.KeyDir, cfg.Presign.MaxTTL)
	if err != nil {
		log.Error("load presign signer", "error", err)
		return 1
	}

	reaper := gc.New(db, blobs, log, gc.Config{Interval: cfg.GC.Interval, Grace: cfg.GC.Grace})
	go reaper.Run(ctx)

	handler := httpapi.NewServer(httpapi.Options{
		Config:     cfg,
		Store:      db,
		Blobs:      blobs,
		Authorizer: authorizer,
		Signer:     signer,
		Logger:     log,
		Version:    version,
		Reaper:     reaper,
	}).Handler()

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ListenPort)))
	if err != nil {
		log.Error("listen", "error", err)
		return 1
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	log.Info("HTTP server serving", "addr", listener.Addr().String())

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server failed", "error", err)
			return 1
		}
		return 0
	case <-ctx.Done():
	}

	log.Info("shutdown signal received, draining", "timeout", shutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Warn("graceful shutdown timed out, closing", "error", err)
		_ = server.Close()
	}
	log.Info("shutdown complete")
	return 0
}

// runStatus prints the redacted effective configuration.
func runStatus(cfg *config.Config) int {
	for _, line := range cfg.Redacted() {
		fmt.Println(line)
	}
	return 0
}

// runDoctor checks the database, the migrations, the file directories and the
// IAM reachability. An unconfigured IAM base URL is reported as SKIP.
func runDoctor(cfg *config.Config, log *slog.Logger) int {
	ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
	defer cancel()

	failed := false
	pass := func(name, detail string) {
		fmt.Printf("PASS %-12s %s\n", name, detail)
	}
	fail := func(name string, err error) {
		failed = true
		fmt.Printf("FAIL %-12s %v\n", name, err)
	}

	if strings.TrimSpace(cfg.ConnectionString) == "" {
		fail("postgres", errors.New("a connection string is required (-dsn or "+config.EnvDSN+")"))
	} else if db, err := store.Open(ctx, cfg.ConnectionString, log); err != nil {
		fail("postgres", err)
	} else {
		defer db.Close()
		pass("postgres", "connected to "+config.RedactDSN(cfg.ConnectionString))
		started := time.Now()
		applied, err := db.Migrate(ctx)
		if err != nil {
			fail("migrations", err)
		} else {
			pass("migrations", fmt.Sprintf("version %d in %s", applied, time.Since(started).Round(time.Millisecond)))
		}
	}

	if blobs, err := blob.Open(cfg.BlobDir); err != nil {
		fail("blob-dir", err)
	} else if err := blobs.Writable(); err != nil {
		fail("blob-dir", err)
	} else {
		pass("blob-dir", "writable: "+cfg.BlobDir)
	}

	if _, err := presign.Load(cfg.KeyDir, cfg.Presign.MaxTTL); err != nil {
		fail("key-dir", err)
	} else {
		pass("key-dir", "writable: "+cfg.KeyDir)
	}

	if strings.TrimSpace(cfg.IAM.BaseURL) == "" {
		fmt.Printf("SKIP %-12s %s is not configured\n", "iam", config.EnvTeamusersBaseURL)
	} else {
		options := iamauthOptions(cfg, log)
		authorizer, err := iamauth.NewAuthorizer(options)
		if err != nil {
			fail("iam", err)
		} else {
			defer authorizer.Close()
			if err := authorizer.Healthy(ctx); err != nil {
				fail("iam", err)
			} else {
				pass("iam", "reachable: "+cfg.IAM.BaseURL)
			}
		}
	}

	if failed {
		return 1
	}
	return 0
}

// runRegisterPermissions idempotently registers the permission catalog in
// teamusers and prints every registered key.
func runRegisterPermissions(cfg *config.Config, log *slog.Logger, token string) int {
	if strings.TrimSpace(cfg.IAM.BaseURL) == "" {
		log.Error("invalid configuration", "error", config.EnvTeamusersBaseURL+" (or -teamusers-base-url) is required")
		return 2
	}
	if strings.TrimSpace(token) == "" {
		token = cfg.IAM.ServiceToken
	}
	if strings.TrimSpace(token) == "" {
		log.Error("invalid configuration", "error", "an admin token is required (-token or "+config.EnvTeamusersAdminToken+")")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	keys, err := iamauth.Register(ctx, cfg.IAM.BaseURL, token, nil, log)
	if err != nil {
		log.Error("register permissions", "error", err)
		return 1
	}
	for _, key := range keys {
		fmt.Println(key)
	}
	log.Info("permissions registered", "count", len(keys))
	return 0
}

func iamauthOptions(cfg *config.Config, log *slog.Logger) iamauth.Options {
	return iamauth.Options{
		BaseURL:      cfg.IAM.BaseURL,
		Issuer:       cfg.IAM.Issuer,
		Audience:     cfg.IAM.Audience,
		ServiceToken: cfg.IAM.ServiceToken,
		ClientID:     cfg.IAM.ClientID,
		ClientSecret: cfg.IAM.ClientSecret,
		NATSURL:      cfg.IAM.NATSURL,
		Timeout:      cfg.IAM.Timeout,
		Logger:       log,
	}
}

func newLogger(cfg *config.Config) (*slog.Logger, error) {
	level, err := cfg.LogLevelValue()
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler).With("service", serviceName, "node_id", cfg.NodeID, "version", version), nil
}
