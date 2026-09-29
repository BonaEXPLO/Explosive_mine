package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"explosive/internal/p2p"
)

const (
	defaultListenAddr = ":8444"

	// Official EXPLOSIVE NetworkID derived from the immutable genesis.
	officialNetworkID = "3aea0eefc0225904726b65729b9d197c62d55ae6514e6576dc273e3f06951398"
)

func main() {
	listenAddr := strings.TrimSpace(os.Getenv("EXPLOSIVE_RELAY_ADDR"))
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		log.Fatalf("invalid relay listen address %q: %v", listenAddr, err)
	}

	tlsCert, err := generateRelayTLSCertificate()
	if err != nil {
		log.Fatalf("failed to generate relay TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{
			tlsCert,
		},
		NextProtos: []string{
			"explosive-relay-v1",
		},
	}

	config := p2p.DefaultRelayServerConfig()
	config.TLSConfig = tlsConfig
	config.NetworkID = officialNetworkID

	server := p2p.NewRelayServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(
		sigs,
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer signal.Stop(sigs)

	serverErr := make(chan error, 1)

	go func() {
		log.Printf(
			"[relay] EXPLOSIVE relay server listening on %s",
			listenAddr,
		)
		log.Printf(
			"[relay] NetworkID: %s",
			officialNetworkID,
		)

		serverErr <- server.ListenAndServe(
			ctx,
			listenAddr,
		)
	}()

	select {
	case sig := <-sigs:
		log.Printf("[relay] shutdown signal received: %s", sig)

	case err := <-serverErr:
		if err != nil {
			log.Printf("[relay] server stopped with error: %v", err)
		}
	}

	cancel()
	server.Close()

	log.Printf("[relay] server stopped")
}

func generateRelayTLSCertificate() (tls.Certificate, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(
		rand.Reader,
		serialLimit,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			CommonName:   "EXPLOSIVE Relay Server",
			Organization: []string{"EXPLOSIVE"},
		},

		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		DNSNames: []string{
			"explosive-relay",
		},

		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		publicKey,
		privateKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	cert, err := tls.X509KeyPair(
		certPEM,
		keyPEM,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"build TLS key pair: %w",
			err,
		)
	}

	return cert, nil
}
