package main

import (
	context "context"
	"errors"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/consul/proto-public/pbconnectca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type testCAHandler struct {
	watchRoots func(request *pbconnectca.WatchRootsRequest, stream pbconnectca.ConnectCAService_WatchRootsServer) error
	sign       func(ctx context.Context, request *pbconnectca.SignRequest) (*pbconnectca.SignResponse, error)
}

func (c *testCAHandler) WatchRoots(request *pbconnectca.WatchRootsRequest, stream pbconnectca.ConnectCAService_WatchRootsServer) error {
	if c.watchRoots == nil {
		return errors.New("unimplemented")
	}
	return c.watchRoots(request, stream)
}

func (c *testCAHandler) Sign(ctx context.Context, request *pbconnectca.SignRequest) (*pbconnectca.SignResponse, error) {
	if c.sign == nil {
		return nil, errors.New("unimplemented")
	}
	return c.sign(ctx, request)
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

func TestCAExample(t *testing.T) {
	for _, tt := range []struct {
		name     string
		handler  *testCAHandler
		callback func(ctx context.Context, client pbconnectca.ConnectCAServiceClient)
	}{
		{
			name: "foo bar",
			handler: &testCAHandler{
				sign: func(ctx context.Context, request *pbconnectca.SignRequest) (*pbconnectca.SignResponse, error) {
					return nil, errors.New("foo bar")
				},
			},
			callback: func(ctx context.Context, client pbconnectca.ConnectCAServiceClient) {
				_, err := client.Sign(ctx, &pbconnectca.SignRequest{
					Csr: "something here",
				})
				require.Equal(t, "foo bar", grpc.ErrorDesc(err))
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, runTestServer(t, tt.handler, tt.callback))
		})
	}
}
