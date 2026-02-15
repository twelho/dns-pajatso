package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// ensureFQDN appends a trailing dot if missing.
func ensureFQDN(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func main() {
	var (
		zone       string
		tsigName   string
		tsigSecret string
		ns         string
		listen     string
	)

	cmd := &cobra.Command{
		Use:   "dns-pajatso",
		Short: "Minimal DNS server for ACME DNS-01 challenges",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Normalize FQDNs.
			zone = ensureFQDN(zone)
			tsigName = ensureFQDN(tsigName)
			ns = ensureFQDN(ns)

			srv := &Server{
				Zone:       zone,
				NS:         ns,
				TsigName:   tsigName,
				TsigSecret: tsigSecret,
				Store:      &Store{},
			}

			// Set up signal handling.
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Start UDP server.
			udpServer := srv.NewDNSServer()
			udpServer.Addr = listen
			udpServer.Net = "udp"

			// Start TCP server.
			tcpServer := srv.NewDNSServer()
			tcpServer.Addr = listen
			tcpServer.Net = "tcp"

			errCh := make(chan error, 2)
			go func() { errCh <- udpServer.ListenAndServe() }()
			go func() { errCh <- tcpServer.ListenAndServe() }()

			fmt.Printf("dns-pajatso serving zone %s on %s (UDP+TCP)\n", zone, listen)

			select {
			case err := <-errCh:
				return fmt.Errorf("server error: %w", err)
			case <-ctx.Done():
				fmt.Println("\nshutting down...")
				udpServer.Shutdown(context.Background())
				tcpServer.Shutdown(context.Background())
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&zone, "zone", "", "DNS zone (e.g. example.com.)")
	cmd.Flags().StringVar(&tsigName, "tsig-name", "", "TSIG key name (e.g. acme-update.)")
	cmd.Flags().StringVar(&tsigSecret, "tsig-secret", "", "Base64 HMAC-SHA512 secret")
	cmd.Flags().StringVar(&ns, "ns", "", "NS hostname (e.g. ns1.example.com.)")
	cmd.Flags().StringVar(&listen, "listen", ":53", "Listen address")

	cmd.MarkFlagRequired("zone")
	cmd.MarkFlagRequired("tsig-name")
	cmd.MarkFlagRequired("tsig-secret")
	cmd.MarkFlagRequired("ns")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
