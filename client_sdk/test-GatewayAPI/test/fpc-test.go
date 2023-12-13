package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/pkg/errors"

	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"crypto/x509"
)

// const (
// 	configPath    = "path_to_your_config.yaml"
// 	channelName   = "mychannel"
// 	chaincodeName = "mycc"
// )

type signer struct {
	f identity.Sign
}

func (s *signer) Sign(in []byte) ([]byte, error) {
	return s.f(in)
}

func main() {
	// // // Create a Fabric Gateway client
	// // wallet, err := gateway.NewFileSystemWallet("wallet")
	// // if err != nil {
	// // 	log.Fatalf("Failed to create wallet: %v", err)
	// // }

	// // if !wallet.Exists("User1") {
	// // 	log.Fatalf("Wallet does not exist: %v", err)
	// // }

	// // gw, err := gateway.Connect(
	// // 	gateway.WithConfig(config.FromFile(configPath)),
	// // 	gateway.WithIdentity(wallet, "User1"),
	// // )
	// // if err != nil {
	// // 	log.Fatalf("Failed to connect to gateway: %v", err)
	// // }
	// defer gw.Close()

	peerEndpoint := os.Getenv("CORE_PEER_ADDRESS")
	gatewayPeer := os.Getenv("CORE_PEER_ID")
	mspPath := os.Getenv("CORE_PEER_MSPCONFIGPATH")
	mspID := os.Getenv("CORE_PEER_LOCALMSPID")

	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection(peerEndpoint, gatewayPeer)
	defer clientConnection.Close()

	certPath, err := findSigningCert(mspPath)
	if err != nil {
		panic(err)
	}

	id := newIdentity(mspID, certPath)
	signer := newSigner(path.Join(mspPath, "keystore"))

	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(signer.Sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gw.Close()

	chaincodeName := "basic"
	if ccname := os.Getenv("CC_NAME"); ccname != "" {
		chaincodeName = ccname
	}

	channelName := "mychannel"
	if cname := os.Getenv("CHANNEL_NAME"); cname != "" {
		channelName = cname
	}

	network := gw.GetNetwork(channelName)
	//contract := network.GetContract(chaincodeName)
	ercc := network.GetContract("ercc")

	endpoints := fetchFPCEndpoints(ercc, chaincodeName)

	if len(endpoints) != 1 {
		panic("need to get single endpoints ")
	}

	fmt.Printf("fppc endpoints: %v\n", endpoints)

	connection := newGrpcConnection(endpoints[0], gatewayPeer)
	fpcPeer := peer.NewEndorserClient(connection)

	fmt.Printf("fpc peer: %v\n", fpcPeer)

	// Get the network and ERCC contract
	// network, err := gw.GetNetwork(channelName)
	// if err != nil {
	// 	log.Fatalf("Failed to get network: %v", err)
	// }
	// erccContract := network.GetContract("ercc")

	// Evaluate the getEnclavePeerEndpoint transaction
	// enclavePeerEndpoint, err := erccContract.EvaluateTransaction("queryChaincodeEndPoints")
	// if err != nil {
	// 	log.Fatalf("Failed to evaluate transaction: %v", err)
	// }

	// fmt.Printf("Enclave Peer Endpoint: %s\n", string(enclavePeerEndpoint))

	// // Establish a new gRPC connection to the enclave peer
	// enclaveClientConnection, err := newEnclaveGrpcConnection(string(enclavePeerEndpoint))
	// if err != nil {
	// 	log.Fatalf("Failed to establish gRPC connection to enclave peer: %v", err)
	// }
	// defer enclaveClientConnection.Close()

	// // Invoke FPC chaincode via direct gRPC connection
	// err = invokeFPCChaincode(enclaveClientConnection)
	// if err != nil {
	// 	log.Fatalf("Failed to invoke FPC chaincode: %v", err)
	// }

	// fmt.Println("Successfully invoked FPC chaincode")
}

func newGrpcConnection(peerEndpoint, gatewayPeer string) *grpc.ClientConn {

	tlsCertPath := os.Getenv("CORE_PEER_TLS_ROOTCERT_FILE")

	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

func fetchFPCEndpoints(contract *client.Contract, chaincodeName string) []string {
	evaluateResult, err := contract.EvaluateTransaction("queryChaincodeEncryptionKey", chaincodeName)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}

	return strings.Split(string(evaluateResult), ",")
}

func findSigningCert(mspConfigPath string) (string, error) {

	p := filepath.Join(mspConfigPath, "signcerts")
	files, err := os.ReadDir(p)
	if err != nil {
		return "", errors.Wrapf(err, "error while searching pem in %s", mspConfigPath)
	}

	// return first pem we find
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".pem") {
			return filepath.Join(p, f.Name()), nil
		}
	}

	return "", errors.Errorf("cannot find pem in %s", mspConfigPath)
}

func newIdentity(mspID, certPath string) *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func newSigner(keyPath string) *signer {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return &signer{f: sign}
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// func newEnclaveGrpcConnection(enclavePeerEndpoint string) (*grpc.ClientConn, error) {

// 	cert, err := tls.LoadX509KeyPair(tlsCertPath, keyPath)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not load client key pair: %s", err)
// 	}

// 	// Create a certificate pool
// 	certPool, err := x509.SystemCertPool()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get system cert pool: %s", err)
// 	}

// 	// Create the credentials and return them
// 	config := &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		RootCAs:      certPool,
// 	}
// 	netConn, err := grpc.Dial(enclavePeerEndpoint, grpc.WithTransportCredentials(credentials.NewTLS(config)))
// 	if err != nil {
// 		return nil, fmt.Errorf("did not connect: %s", err)
// 	}

// 	return netConn, nil
// }

// func invokeFPCChaincode(enclaveClientConnection *grpc.ClientConn) error {
// 	// Create a new gRPC client for the FPC chaincode
// 	client := gateway.NewGatewayClient(enclaveClientConnection)

// 	// Create the context for the transaction
// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
// 	defer cancel()

// 	// Create a new transaction
// 	transaction, err := client.NewTransaction(ctx, &gateway.NewTransactionRequest{
// 		ChannelId:     "mychannel",
// 		ChaincodeId:   "mycc",
// 		TransactionId: "tx1",
// 		Args:          [][]byte{[]byte("arg1"), []byte("arg2")},
// 	})

// 	if err != nil {
// 		return fmt.Errorf("failed to create new transaction: %w", err)
// 	}

// 	// Submit the transaction
// 	_, err = client.Submit(ctx, &gateway.SubmitRequest{
// 		TransactionId: transaction.TransactionId,
// 		ChannelId:     "mychannel",
// 	})
// 	if err != nil {
// 		return fmt.Errorf("failed to submit transaction: %w", err)
// 	}

// 	return nil
// }

// func (c *contractImpl) getPeerEndpoints() (string, error) {
// 	if len(c.peerEndpoints) == 0 {
// 		resp, err := c.ercc.EvaluateTransaction("queryChaincodeEndPoints", c.Name())
// 		if err != nil {
// 			return "", err
// 		}
// 		c.peerEndpoints = strings.Split(string(resp), ",")
// 	}
// 	return c.peerEndpoints[0], nil
// }
