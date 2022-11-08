package main

import (
	"bytes"
	context "context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/consul/proto-public/pbconnectca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type testCAHandler struct {
	ca     *CertificateInfo
	rotate chan struct{}

	mutex sync.RWMutex
}

func newHandler() *testCAHandler {
	return &testCAHandler{
		ca:     DefaultTestCA,
		rotate: make(chan struct{}),
	}
}

func (c *testCAHandler) WatchRoots(request *pbconnectca.WatchRootsRequest, stream pbconnectca.ConnectCAService_WatchRootsServer) error {
	writeCertificate := func() error {
		c.mutex.RLock()
		ca := string(c.ca.CertBytes)
		c.mutex.RUnlock()

		if err := stream.Send(&pbconnectca.WatchRootsResponse{
			ActiveRootId: "test",
			Roots: []*pbconnectca.CARoot{{
				Id:       "test",
				RootCert: ca,
			}},
		}); err != nil {
			return err
		}
		return nil
	}

	// do initial write
	if err := writeCertificate(); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-c.rotate:
			if err := writeCertificate(); err != nil {
				return err
			}
	}
}

func (c *testCAHandler) Rotate() {
	rootCA, err := GenerateSignedCertificate(GenerateCertificateOptions{
		IsCA: true,
	})
	if err != nil {
		panic(err)
	}

	c.mutex.Lock()
	c.ca = rootCA
	c.mutex.Unlock()

	c.rotate <- struct{}{}
}

func (c *testCAHandler) Sign(ctx context.Context, request *pbconnectca.SignRequest) (*pbconnectca.SignResponse, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	raw, err := base64.URLEncoding.DecodeString(request.Csr)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       c.ca.Cert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certData, err := x509.CreateCertificate(rand.Reader, &template, c.ca.Cert, template.PublicKey, c.ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	var certificatePEM bytes.Buffer
	if err := pem.Encode(&certificatePEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	}); err != nil {
		return nil, err
	}

	return &pbconnectca.SignResponse{
		CertPem: certificatePEM.String(),
	}, nil
}

func retryRequest(retry func(ctx context.Context) error) error {
	return backoff.Retry(func() error {
		ctx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer timeoutCancel()

		err := retry(ctx)

		// grpc errors don't wrap errors normally, so just check the error text
		// deadline exceeded == canceled context
		// connection refused == no open port
		// EOF == no response yet on a stream
		// check for file existence if it's a unix socket
		if err != nil && (strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "EOF") ||
			os.IsNotExist(err)) {
			return err
		}
		return backoff.Permanent(err)
		// try for up to 5 seconds
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(10*time.Millisecond), 500))
}

func runTestServer(t *testing.T, handler *testCAHandler, callback func(ctx context.Context, client pbconnectca.ConnectCAServiceClient)) error {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	directory, err := os.MkdirTemp("", "example-test")
	require.NoError(t, err)
	defer os.RemoveAll(directory)
	socketPath := path.Join(directory, "sds.sock")

	server := grpc.NewServer()
	pbconnectca.RegisterConnectCAServiceServer(server, handler)
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	errEarlyTestTermination := errors.New("early termination")
	done := make(chan error, 1)
	go func() {
		defer func() {
			// write an error to the channel, if
			// the server canceled successfully the err will be nil
			// and the read will get that first, this will only
			// be read if we have some early expectation that calls
			// runtime.Goexit prior to the server stopping
			done <- errEarlyTestTermination
		}()
		done <- server.Serve(listener)
	}()
	// wait until the server socket exists
	err = retryRequest(func(_ context.Context) error {
		_, err := os.Stat(socketPath)
		return err
	})
	require.NoError(t, err)

	conn, err := grpc.DialContext(ctx, "unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	client := pbconnectca.NewConnectCAServiceClient(conn)

	if callback != nil {
		func() {
			defer cancel()

			callback(ctx, client)
		}()
	}
	select {
	case err := <-done:
		if err != nil {
			require.NotErrorIs(t, err, errEarlyTestTermination)
		}
	case <-ctx.Done():
		server.Stop()
	}

	return nil
}

func TestWatcher(t *testing.T) {
	handler := newHandler()

	runTestServer(t, handler, func(ctx context.Context, client pbconnectca.ConnectCAServiceClient) {
		watcher := NewCertWatcher("/ns/default/dc/testing/svc/test-service", client)
		require.Equal(t, "", watcher.Root())
		require.Equal(t, "", watcher.Certificate())

		done := make(chan error, 1)
		go func() {
			done <- watcher.Watch(ctx)
		}()

		time.Sleep(100 * time.Millisecond)
		firstRoot := watcher.Root()
		firstCert := watcher.Certificate()

		require.NotEqual(t, "", firstRoot)
		require.NotEqual(t, "", firstCert)

		handler.Rotate()

		time.Sleep(100 * time.Millisecond)
		secondRoot := watcher.Root()
		secondCert := watcher.Certificate()

		require.NotEqual(t, "", secondRoot)
		require.NotEqual(t, "", secondCert)
		require.NotEqual(t, firstRoot, secondRoot)
		require.NotEqual(t, firstCert, secondCert)

		select {
		case err := <-done:
			require.NoError(t, err)
		case <-ctx.Done():
		default:
		}
	})
}
