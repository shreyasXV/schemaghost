package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		MinVersion: tls.VersionTLS12,
	}
}

// mockSSLServer simulates upstream Postgres SSLRequest negotiation.
// response is the byte to reply after receiving SSLRequest ('S', 'N', or anything else).
func mockSSLServer(t *testing.T, response byte, tlsConfig *tls.Config) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()

				var buf [8]byte
				if _, err := io.ReadFull(c, buf[:]); err != nil {
					return
				}
				length := binary.BigEndian.Uint32(buf[0:4])
				code := binary.BigEndian.Uint32(buf[4:8])
				if length != 8 || code != 80877103 {
					return
				}

				c.Write([]byte{response})

				if response == 'S' && tlsConfig != nil {
					tlsConn := tls.Server(c, tlsConfig)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					startupLen := make([]byte, 4)
					io.ReadFull(tlsConn, startupLen)
				}
			}(conn)
		}
	}()

	return ln
}

func mockPlainServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				lenBuf := make([]byte, 4)
				if _, err := io.ReadFull(c, lenBuf); err != nil {
					return
				}
				msgLen := int(binary.BigEndian.Uint32(lenBuf))
				if msgLen > 4 {
					discard := make([]byte, msgLen-4)
					io.ReadFull(c, discard)
				}
			}(conn)
		}
	}()

	return ln
}

func TestDialUpstream_SSLRequest_Accepted(t *testing.T) {
	serverTLS := selfSignedTLSConfig(t)
	ln := mockSSLServer(t, 'S', serverTLS)
	defer ln.Close()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := dialUpstream(ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("dialUpstream failed: %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatal("expected *tls.Conn, got plain connection")
	}
}

func TestDialUpstream_SSLRequest_Rejected(t *testing.T) {
	ln := mockSSLServer(t, 'N', nil)
	defer ln.Close()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	_, err := dialUpstream(ln.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("expected error when server rejects TLS, got nil")
	}
	if got := err.Error(); got != "upstream does not support TLS but UPSTREAM_TLS was set" {
		t.Fatalf("unexpected error message: %s", got)
	}
}

func TestDialUpstream_SSLRequest_UnexpectedByte(t *testing.T) {
	ln := mockSSLServer(t, 'E', nil)
	defer ln.Close()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	_, err := dialUpstream(ln.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("expected error for unexpected response byte, got nil")
	}
	expected := "unexpected SSLRequest response from upstream: 0x45"
	if got := err.Error(); got != expected {
		t.Fatalf("unexpected error: got %q, want %q", got, expected)
	}
}

func TestDialUpstream_PlainConnection(t *testing.T) {
	ln := mockPlainServer(t)
	defer ln.Close()

	conn, err := dialUpstream(ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dialUpstream (plain) failed: %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*tls.Conn); ok {
		t.Fatal("expected plain net.Conn, got *tls.Conn")
	}
}

func TestDialUpstream_SSLRequest_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var buf [8]byte
				io.ReadFull(c, buf[:])
				time.Sleep(10 * time.Second)
			}(conn)
		}
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	start := time.Now()
	_, err = dialUpstream(ln.Addr().String(), clientTLS)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 7*time.Second {
		t.Fatalf("dialUpstream took too long (%v) — deadline not working", elapsed)
	}
}

func TestDialUpstream_SSLRequest_WireFormat(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	received := make(chan [8]byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var buf [8]byte
		io.ReadFull(conn, buf[:])
		received <- buf
		conn.Write([]byte{'N'})
	}()

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	dialUpstream(ln.Addr().String(), clientTLS)

	select {
	case buf := <-received:
		gotLen := binary.BigEndian.Uint32(buf[0:4])
		gotCode := binary.BigEndian.Uint32(buf[4:8])
		if gotLen != 8 {
			t.Errorf("SSLRequest length: got %d, want 8", gotLen)
		}
		if gotCode != 80877103 {
			t.Errorf("SSLRequest code: got %d, want 80877103", gotCode)
		}
		expectedBytes := [8]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
		if buf != expectedBytes {
			t.Errorf("SSLRequest raw bytes: got %x, want %x", buf, expectedBytes)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSLRequest bytes")
	}
}
