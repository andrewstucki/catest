package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/hashicorp/consul/proto-public/pbconnectca"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type CertWatcher struct {
	root   string
	cert   string
	domain string

	// this needs to be the service path for the spiffe id we want generated
	servicePath string

	client pbconnectca.ConnectCAServiceClient
	mutex  sync.RWMutex
}

func NewCertWatcher(path string, client pbconnectca.ConnectCAServiceClient) *CertWatcher {
	return &CertWatcher{
		servicePath: path,
		client:      client,
	}
}

func (w *CertWatcher) Watch(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)

	roots := make(chan *pbconnectca.WatchRootsResponse)

	group.Go(func() error {
		return w.retry(ctx, roots, w.watchRoots)
	})
	group.Go(func() error {
		return w.retry(ctx, roots, w.watchCerts)
	})

	return group.Wait()
}

func (w *CertWatcher) Root() string {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	return w.root
}

func (w *CertWatcher) Certificate() string {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	return w.cert
}

type watchFn func(ctx context.Context, rotatedRootCh chan *pbconnectca.WatchRootsResponse) error

func (w *CertWatcher) retry(ctx context.Context, rotatedRootCh chan *pbconnectca.WatchRootsResponse, fn watchFn) error {
	// TODO: wrap this in some retry logic
	return fn(ctx, rotatedRootCh)
}

func (w *CertWatcher) watchRoots(ctx context.Context, rotatedRootCh chan *pbconnectca.WatchRootsResponse) error {
	stream, err := w.client.WatchRoots(ctx, &pbconnectca.WatchRootsRequest{})
	if err != nil {
		return err
	}
	for {
		root, err := stream.Recv()
		if err != nil {
			return err
		}
		select {
		case rotatedRootCh <- root:
		case <-ctx.Done():
			return nil
		}
	}
}

func (w *CertWatcher) watchCerts(ctx context.Context, rotatedRootCh chan *pbconnectca.WatchRootsResponse) error {
	var err error
	// make sure we trigger the root fetch first
	expiration := time.Duration(math.MaxInt64)

	for {
		select {
		case r := <-rotatedRootCh:
			root := getRoot(r)
			if r == nil {
				// this shouldn't ever really happen?
				continue
			}
			w.mutex.Lock()
			w.root = root.RootCert
			w.domain = r.TrustDomain
			expiration, err = w.fetchCert(ctx)
			w.mutex.Unlock()
			if err != nil {
				return err
			}
		case <-time.After(expiration / 2):
			w.mutex.Lock()
			expiration, err = w.fetchCert(ctx)
			w.mutex.Unlock()
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// must be called with the mutex held
func (w *CertWatcher) fetchCert(ctx context.Context) (time.Duration, error) {
	csr, err := w.generateCSR()
	if err != nil {
		return 0, err
	}
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
	response, err := w.client.Sign(ctx, &pbconnectca.SignRequest{
		Csr: string(data),
	})
	if err != nil {
		return 0, err
	}
	block, _ := pem.Decode([]byte(response.CertPem))
	if block == nil {
		return 0, errors.New("invalid block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, err
	}
	w.cert = response.CertPem
	return time.Until(certificate.NotAfter), nil
}

func (w *CertWatcher) generateCSR() ([]byte, error) {
	// TODO: fill this in with actual implementation
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs: []*url.URL{w.generateSPIFFE()},
		Subject: pkix.Name{
			Organization:  []string{"Testing, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Fake Street"},
			PostalCode:    []string{"11111"},
		},
	}, privateKey)
}

func (w *CertWatcher) generateSPIFFE() *url.URL {
	var svid url.URL
	svid.Scheme = "spiffe"
	svid.Host = w.domain
	svid.Path = w.servicePath
	return &svid
}

func getRoot(response *pbconnectca.WatchRootsResponse) *pbconnectca.CARoot {
	id := response.ActiveRootId
	for _, root := range response.Roots {
		if root.Id == id {
			return root
		}
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "localhost:8502", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	client := pbconnectca.NewConnectCAServiceClient(conn)

	watcher := NewCertWatcher("/ns/default/dc/dc1/svc/test", client)
	go func() {
		if err := watcher.Watch(ctx); err != nil {
			select {
			case <-ctx.Done():
			default:
				panic(err)
			}
		}
	}()

	time.Sleep(1 * time.Second)
	fmt.Println("Certificate:", watcher.Certificate())
	fmt.Println("Root:", watcher.Root())
}
