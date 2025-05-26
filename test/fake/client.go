package fake

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k8sgateway/internal/httpproxy"
)

// Client is a Kubernetes client that connects to the API server through the proxy.
type Client struct {
	*kubernetes.Clientset
	// conn is the underlying connection to the proxy.
	conn net.Conn
}

// NewClient setup a connection to the proxy by simulating Twingate client's interaction with
// the proxy, and returns a Client that uses the proxy connection.
func NewClient(proxyAddress, controllerURL, apiServerURL string) *Client {
	logger := log.New(os.Stdout, "fake-client:", log.LstdFlags)

	gat := fetchGAT(controllerURL, logger)
	if gat == "" {
		return nil
	}

	// Proxy cert
	caCert, _ := os.ReadFile("../data/proxy/cert.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "127.0.0.1",
		RootCAs:    caCertPool,
	}

	// Manually create a TCP connection
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		logger.Printf("Failed to connect to proxy: %v", err)

		return nil
	}

	// Enable outer TLS (between Twingate client and proxy)
	proxyTLSConn := tls.Client(conn, tlsConfig)
	if err := proxyTLSConn.Handshake(); err != nil {
		logger.Printf("Client TLS handshake failed: %v", err)

		return nil
	}

	// Create CONNECT request
	connectReq, err := http.NewRequest(http.MethodConnect, apiServerURL, nil)
	if err != nil {
		logger.Printf("Failed to create request: %v", err)

		return nil
	}

	connectReq.Header.Set("Proxy-Authorization", "Bearer "+gat)

	clientKey, _ := ReadECKey("../data/client/key.pem")
	ekm, _ := httpproxy.ExportKeyingMaterial(proxyTLSConn)
	ekmHash := sha256.Sum256(ekm)
	signature, _ := ecdsa.SignASN1(rand.Reader, clientKey, ekmHash[:])
	b64Signature := base64.StdEncoding.EncodeToString(signature)
	connectReq.Header.Set("X-Token-Signature", b64Signature)

	// Send CONNECT request
	if err := connectReq.Write(proxyTLSConn); err != nil {
		logger.Printf("Failed to write CONNECT request: %v", err)

		return nil
	}

	// Read CONNECT response
	connectResp, err := http.ReadResponse(bufio.NewReader(proxyTLSConn), connectReq)
	if err != nil {
		logger.Printf("Failed to read CONNECT response: %v", err)

		return nil
	}
	defer connectResp.Body.Close()

	logger.Printf("CONNECT response %d", connectResp.StatusCode)

	if connectResp.StatusCode != http.StatusOK {
		logger.Printf("Failed to connect to proxy: %v", connectResp.Status)

		return nil
	}

	// Setup k8s client using the proxy connection
	config := &rest.Config{
		TLSClientConfig: rest.TLSClientConfig{
			ServerName: "127.0.0.1",
			CAData:     caCert,
		},
		Dial: func(_ctx context.Context, _network, _addr string) (net.Conn, error) {
			return proxyTLSConn, nil
		},
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Printf("Failed to create Kubernetes clientset: %v", err)

		return nil
	}

	return &Client{
		Clientset: clientset,
		conn:      proxyTLSConn,
	}
}

func fetchGAT(controllerURL string, logger *log.Logger) string {
	resp, err := http.Get(controllerURL + "/api/v1/gat")
	if err != nil {
		logger.Printf("Failed to fetch GAT: %v", err)

		return ""
	}
	defer resp.Body.Close()

	gat, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("Failed to read GAT response: %v", err)

		return ""
	}

	return string(gat)
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}
