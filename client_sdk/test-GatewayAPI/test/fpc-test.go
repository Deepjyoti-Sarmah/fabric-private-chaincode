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

type signer struct {
	f identity.Sign
}

func (s *signer) Sign(in []byte) ([]byte, error) {
	return s.f(in)
}

func main() {
	// Create a Fabric Gateway client

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

	// Fetching FPC Endpoints
	network := gw.GetNetwork(channelName)
	ercc := network.GetContract("ercc")
	endpoints := fetchFPCEndpoints(ercc, chaincodeName)

	if len(endpoints) != 1 {
		panic("need to get single endpoints ")
	}

	fmt.Printf("fppc endpoints: %v\n", endpoints)

	// Establishing new gRPC connection with the FPC peer
	connection := newGrpcConnection(endpoints[0], gatewayPeer)
	fpcPeer := peer.NewEndorserClient(connection)

	fmt.Printf("fpc peer: %v\n", fpcPeer)
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