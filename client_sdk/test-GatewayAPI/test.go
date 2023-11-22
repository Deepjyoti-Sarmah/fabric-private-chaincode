package main
// package testgatewayapi

import (
	"context"
	"crypto/x509"
	// "encoding/pem"
	"fmt"
	// "io/ioutil"
	"log"
	// "time"
	"os"
	
	"strings"
	
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-private-chaincode/internal/crypto"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"


	// "github.com/hyperledger/fabric-private-chaincode/internal/utils"
)

const (
	mspID        = "Org1MSP"
	cryptoPath   = "../../test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
)

// Transaction interface that is needed by the FPC contract implementation
type Transaction interface {
	Evaluate(args ...string) ([]byte, error)
}

// contractImpl implements the client-side FPC protocol
type contractImpl struct {
	target        Contract
	ercc          Contract
	peerEndpoints []string
	ep            crypto.EncryptionProvider
}

// Contract interface
type Contract interface {
	Name() string
	EvaluateTransaction(name string, args ...string) ([]byte, error)
	SubmitTransaction(name string, args ...string) ([]byte, error)
	CreateTransaction(name string, peerEndpoints ...string) (Transaction, error)
}

func main() {
	// Connect to the gateway and call ERCC to get the enclave peer endpoint
	enclavePeerEndpoint, err := connectToEnclaveAndFetchEndpoint()
	if err != nil {
		log.Fatalf("Failed to get enclave peer endpoint: %v", err)
	}

	// Establish a new gRPC connection to the enclave peer
	enclaveClientConnection, err := newEnclaveGrpcConnection(enclavePeerEndpoint)
	if err != nil {
		log.Fatalf("Failed to establish gRPC connection to enclave peer: %v", err)
	}
	defer enclaveClientConnection.Close()

	// Call FPC chaincode via direct gRPC connection
	err = invokeFPCChaincode(enclaveClientConnection)
	if err != nil {
		log.Fatalf("Failed to invoke FPC chaincode: %v", err)
	}

	fmt.Println("Successfully invoked FPC chaincode")
}

// Connect to the gateway and call ERCC to get the enclave peer endpoint
func connectToEnclaveAndFetchEndpoint() (string, error) {
	// Load the user identity
	wallet, err := loadIdentity()
	if err != nil {
		return "", err
	}

	// Connect to the gateway
	// gw, err := client.Connect(
	// 	client.WithIdentity(wallet, "User1"),
	// 	client.WithNetwork("mychannel"),
	// 	client.WithEndpoint(peerEndpoint),
	// 	client.WithClientOptions(
	// 		client.WithTLSCert(tlsCertPath),
	// 		client.WithGRPCOptions(grpc.WithBlock()),
	// 	),
	// )

// Connect to the gateway
  gw, err := client.Connect(
    client.WithIdentity(wallet, "User1"),
    client.WithNetwork("mychannel"),
    client.WithEndpoint(peerEndpoint),
    client.WithTLSCert(tlsCertPath),
    client.WithGRPCOptions(grpc.WithBlock()),
  )
  if err != nil {
    log.Fatalf("Failed to connect to gateway: %v", err)
  }
  
  defer gw.Close()

	// Get the ercc contract
	erccContract := gw.GetNetwork("mychannel").GetContract("ercc")

	// get Enclave Peer Endpoint to the function ???????????????????????
	result, err := erccContract.EvaluateTransaction("get Enclave Peer Endpoint")
	// result, err := erccContract.EvaluateTransaction("getPeerEndpoints")
	if err != nil {
		return "", fmt.Errorf("failed to evaluate transaction: %w", err)
	}

	return string(result), nil
}

// Establish a new gRPC connection to the enclave peer
func newEnclaveGrpcConnection(enclavePeerEndpoint string) (*grpc.ClientConn, error) {
	// Load the enclave TLS certificate
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		return nil, err
	}

	// Create a cert pool and add the enclave TLS certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)

	// Create gRPC transport credentials using the enclave TLS certificate pool
	transportCredentials := credentials.NewClientTLSFromCert(certPool, "")

	// Establish a gRPC connection to the enclave peer
	connection, err := grpc.Dial(enclavePeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, err
	}

	return connection, nil
}

// Invoke FPC chaincode via direct gRPC connection
func invokeFPCChaincode(enclaveClientConnection *grpc.ClientConn) error {
	// Create a new gRPC client for the FPC chaincode
	client := gateway.NewGatewayClient(enclaveClientConnection)

	// Create a new transaction
	transaction, err := client.NewTransaction(context.Background(), &gateway.NewTransactionRequest{
		ChannelId:     "mychannel",
		ChaincodeId:   "mycc",
		TransactionId: "tx1",
		Args:          [][]byte{[]byte("arg1"), []byte("arg2")},
	})

	if err != nil {
		return fmt.Errorf("failed to create new transaction: %w", err)
	}

	// Submit the transaction
	_, err = client.Submit(context.Background(), &gateway.SubmitRequest{
		TransactionId: transaction.TransactionId,
		ChannelId:     "mychannel",
		// Endorsers:     []string{"peer0.org1.example.com", "peer0.org2.example.com"},
	})
	if err != nil {
		return fmt.Errorf("failed to submit transaction: %w", err)
	}

	return nil
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

func loadIdentity() (*identity.Wallet, error) {
	// Create a new file system wallet
	wallet, err := identity.NewFileSystemWallet("wallet")
	if err != nil {
		return nil, err
	}

	// Check if the user's identity exists in the wallet
	if !wallet.Exists("User1") {
		// If the user's identity does not exist, create it
		err = createIdentity(wallet)
		if err != nil {
			return nil, err
		}
	}

	return wallet, nil
}


func createIdentity(wallet *identity.Wallet) error {
	// Load the user's certificate
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Load the user's private key
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	// Create a new identity
	identity := identity.NewX509Identity("Org1MSP", certificatePEM, privateKeyPEM)

	// Add the identity to the wallet
	err = wallet.Put("User1", identity)
	if err != nil {
		return fmt.Errorf("failed to put identity into wallet: %w", err)
	}

	return nil
}

func (c *contractImpl) Name() string {
	return c.target.Name()
}

// getPeerEndpoints returns an array of peer endpoints that host the FPC chaincode enclave
// An endpoint is a simple string with the format `host:port`
func (c *contractImpl) getPeerEndpoints() ([]string, error) {
	if len(c.peerEndpoints) == 0 {
		resp, err := c.ercc.EvaluateTransaction("queryChaincodeEndPoints", c.Name())
		if err != nil {
			return nil, err
		}
		c.peerEndpoints = strings.Split(string(resp), ",")
	}
	return c.peerEndpoints, nil
}
