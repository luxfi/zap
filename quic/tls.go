// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// defaultCurvePreferences is the default TLS NamedGroup preference list.
//
// X25519MLKEM768 (IANA 0x11ec) is the hybrid post-quantum key exchange
// jointly defined by Cloudflare / Google / IETF and shipped by Go 1.24+.
// It combines:
//
//   - X25519 (RFC 7748) — classical 128-bit ECC security
//   - ML-KEM-768 (NIST FIPS 203) — Level 3 lattice security
//
// The combined shared secret is HKDF-Extract of X25519_ss || ML-KEM_ss,
// performed inside crypto/tls. We do not reimplement the combiner.
//
// X25519 is kept as a fallback for peers that have not yet adopted the
// hybrid, but it is listed after the hybrid so a PQ-capable peer always
// picks the hybrid first.
//
// We deliberately do not include a hybrid variant outside the IANA
// registry (e.g. a "z-wing" fork). Stay on 0x11ec because every other
// Hanzo / Lux service that ships a TLS 1.3 stack speaks the same group.
var defaultCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.X25519,
}

// defaultSessionTicketLifetime caps the maximum age of a TLS 1.3
// session ticket the server will accept for resumption. Short
// lifetimes blunt the 0-RTT replay window.
const defaultSessionTicketLifetime = time.Hour

// applyZAPDefaults mutates cfg in place to install the ZAP defaults if
// the caller has not already chosen otherwise. Used by both server and
// client. Returns cfg.
//
// The fields we set:
//
//   - MinVersion = TLS 1.3 (lower versions cannot speak X25519MLKEM768
//     because the named-group registry is TLS-1.3-only).
//   - CurvePreferences = [X25519MLKEM768, X25519] if unset.
//   - NextProtos = ["zap/1"] if unset (ALPN allowlist).
//
// We intentionally do NOT default Certificates or VerifyPeerCertificate;
// those are the caller's policy.
func applyZAPDefaults(cfg *tls.Config) *tls.Config {
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS13
	}
	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = append([]tls.CurveID(nil), defaultCurvePreferences...)
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{ALPN}
	} else {
		// Caller supplied ALPN values: enforce that "zap/1" is one of
		// them. Otherwise QUIC negotiation will fail.
		found := false
		for _, p := range cfg.NextProtos {
			if p == ALPN {
				found = true
				break
			}
		}
		if !found {
			// Prepend so we still get a chance to negotiate the
			// ZAP protocol when the caller knows about others.
			cfg.NextProtos = append([]string{ALPN}, cfg.NextProtos...)
		}
	}
	if cfg.SessionTicketsDisabled == false && cfg.ClientSessionCache == nil {
		// Client-side ticket cache; harmless on a server config.
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	}
	return cfg
}

// GenerateSelfSignedCert generates a short-lived self-signed ECDSA-P256
// certificate suitable for testing. NOT for production use: production
// deployments must supply real certificates via tls.Config.Certificates
// or GetCertificate, signed by a trusted CA.
//
// Exposed as a public helper because tests in other packages may want
// to spin up a real ZAP-QUIC server.
func GenerateSelfSignedCert(hosts ...string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost"}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ecdsa keygen: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"ZAP"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// validateNegotiatedALPN is a belt-and-suspenders post-handshake check.
// quic-go already rejects mismatched ALPN at the TLS layer, but we
// re-check so that any future relaxation in quic-go does not silently
// allow non-zap protocols through this transport.
func validateNegotiatedALPN(st tls.ConnectionState) error {
	if st.NegotiatedProtocol != ALPN {
		return errors.New("zap/quic: peer negotiated ALPN " + st.NegotiatedProtocol + ", expected " + ALPN)
	}
	return nil
}
