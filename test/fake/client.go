package fake

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"k8sgateway/internal/httpproxy"
	"k8sgateway/internal/token"
)

const localAddress = "127.0.0.1:9000"

// TODO: Return client and support shutdown
// type Client struct {
// 	Listener net.Listener
// }

func NewClient(proxyAddress, controllerURL, apiServerURL string) {
	// TODO: use zap development
	logger := log.New(os.Stdout, "fake-client:", log.LstdFlags)

	gat := fetchGAT(controllerURL, logger)
	//if gat == "" {
	//	return nil
	//}

	// Listen for incoming connections
	// TODO: listen to a random port
	listener, err := net.Listen("tcp", localAddress)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	//defer listener.Close()
	log.Printf("Listening on %s, forwarding to %s", localAddress, proxyAddress)

	go func() {
		for {
			// Accept new connection
			clientConn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept connection: %v", err)
				continue
			}

			// Handle connection in a goroutine
			go handleConnection(proxyAddress, apiServerURL, clientConn, string(gat))
		}
	}()
}

func handleConnection(proxyAddress, apiServerURL string, clientConn net.Conn, gat string) {
	defer clientConn.Close()

	// Proxy certs
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
		fmt.Printf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Enable outer TLS (between Twingate client and proxy)
	proxyTLSConn := tls.Client(conn, tlsConfig)
	if err := proxyTLSConn.Handshake(); err != nil {
		fmt.Printf("TLS handshake failed(proxy): %v", err)
	}

	// Create CONNECT request
	connectReq, err := http.NewRequest(http.MethodConnect, apiServerURL, nil)
	if err != nil {
		fmt.Printf("Failed to create request: %v", err)
	}

	connectReq.Header.Set("Proxy-Authorization", fmt.Sprintf("Bearer %s", gat))

	clientKey, _ := ReadECKey("../data/client/key.pem")
	ekm, _ := httpproxy.ExportKeyingMaterial(proxyTLSConn)
	ekmHash := sha256.Sum256(ekm)
	signature, _ := ecdsa.SignASN1(rand.Reader, clientKey, ekmHash[:])
	b64Signature := base64.StdEncoding.EncodeToString(signature)
	connectReq.Header.Set("X-Token-Signature", b64Signature)

	// Send CONNECT request
	if err := connectReq.Write(proxyTLSConn); err != nil {
		fmt.Printf("Failed to write CONNECT request: %v", err)
	}

	// Read CONNECT response
	connectResp, err := http.ReadResponse(bufio.NewReader(proxyTLSConn), connectReq)
	if err != nil {
		fmt.Printf("Failed to read CONNECT response: %v", err)
	}

	fmt.Println("Response", connectResp.StatusCode)

	// Set up bidirectional copy
	go func() {
		if _, err := io.Copy(proxyTLSConn, clientConn); err != nil {
			log.Printf("Error copying client->proxy: %v", err)
		}
	}()

	if _, err := io.Copy(clientConn, proxyTLSConn); err != nil {
		log.Printf("Error copying proxy->client: %v", err)
	}
}

func fetchGAT(controllerURL string, logger *log.Logger) string {
	clientPublicKey, _ := ReadECKey("../data/client/key.pem")
	requestBody := requestBody{
		ClientPublicKey: &token.PublicKey{
			PublicKey: clientPublicKey.PublicKey,
		},
		User: &token.User{
			ID:       "user-1",
			Username: "alex@acme.com",
			Groups:   []string{"OnCall", "Engineering"},
		},
		Device: &token.Device{
			ID: "device-1",
		},
		Resource: &token.Resource{
			ID:      "resource-1",
			Address: "127.0.0.1",
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		logger.Printf("Failed to marshal request body: %v", err)
		return ""
	}

	resp, err := http.Post(controllerURL+"/api/v1/gat", "application/json", bytes.NewBuffer(jsonData))
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
