// // package main

// // import (
// // 	"fmt"
// // 	"net/http"

// // 	"github.com/hyperledger/fabric-gateway/pkg/client"
// // 	"github.com/hyperledger/fabric-gateway/pkg/identity"
// // 	// "github.com/hyperledger/fabric-sdk-go/pkg/gateway"
// // )

// // type OrgSetup struct {
// // 	OrgName      string
// // 	MSPID        string
// // 	CryptoPath   string
// // 	CertPath     string
// // 	KeyPath      string
// // 	TLSCertPath  string
// // 	PeerEndpoint string
// // 	GatewayPeer  string
// // 	Gateway      *client.Gateway
// // }

// // func (setup *OrgSetup) Connect() error {
// // 	connectionOptions := &client.ConnectionOptions{
// // 		Identity: identity.NewX509Identity(setup.MSPID, setup.CertPath, setup.KeyPath),
// // 		Endpoint: setup.GatewayPeer,
// // 	}
// // 	gateway, err := client.Connect(connectionOptions)
// // 	if err != nil {
// // 		return err
// // 	}
// // 	setup.Gateway = gateway
// // 	return nil
// // }

// // // func (setup *OrgSetup) Query(w http.ResponseWriter, r *http.Request) {
// // // 	// Implement the logic for the Query endpoint
// // // }

// // // func (setup *OrgSetup) Invoke(w http.ResponseWriter, r *http.Request) {
// // 	// Implement the logic for the Invoke endpoint
// // // }

// // func Serve(setup *OrgSetup) {
// // 	http.HandleFunc("/query", setup.Query)
// // 	http.HandleFunc("/invoke", setup.Invoke)
// // 	fmt.Println("Listening (http://localhost:3000/)...")
// // 	if err := http.ListenAndServe(":3000", nil); err != nil {
// // 		fmt.Println(err)
// // 	}
// // }

// // func main() {
// // 	setup := &OrgSetup{
// // 		OrgName:      "Org1",
// // 		MSPID:        "Org1MSP",
// // 		CryptoPath:   "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp",
// // 		CertPath:     "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem",
// // 		KeyPath:      "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore",
// // 		TLSCertPath:  "crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
// // 		PeerEndpoint: "localhost:7051",
// // 		GatewayPeer:  "localhost:7051",
// // 	}
// // 	if err := setup.Connect(); err != nil {
// // 		fmt.Println("Failed to connect to Gateway: ", err)
// // 		return
// // 	}
// // 	Serve(setup)
// // }

// package main

// import (
// 	"fmt"

// 	"github.com/hyperledger/fabric-gateway/pkg/client"
// 	"github.com/hyperledger/fabric-gateway/pkg/identity"
// 	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
// )

// type OrgSetup struct {
// 	OrgName      string
// 	MSPID        string
// 	CryptoPath   string
// 	CertPath     string
// 	KeyPath      string
// 	TLSCertPath  string
// 	PeerEndpoint string
// 	GatewayPeer  string
// 	Gateway      *client.Gateway
// }

// func (setup *OrgSetup) Connect() error {
// 	connectionOptions := &client.ConnectionOptions{
// 		Identity: identity.NewX509Identity(setup.MSPID, setup.CertPath, setup.KeyPath),
// 		Endpoint: setup.GatewayPeer,
// 	}
// 	gateway, err := client.Connect(connectionOptions)
// 	if err != nil {
// 		return err
// 	}
// 	setup.Gateway = gateway
// 	return nil
// }

// func (setup *OrgSetup) GetContract(chaincodeID string) (gateway.Contract, error) {
// 	network, err := setup.Gateway.GetNetwork("mychannel")
// 	if err != nil {
// 		return err
// 	}
// 	contract := network.GetContract(chaincodeID)
// 	return contract, nil
// }

// func main() {
// 	setup := &OrgSetup{
// 		OrgName:      "Org1",
// 		MSPID:        "Org1MSP",
// 		CryptoPath:   "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp",
// 		CertPath:     "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem",
// 		KeyPath:      "crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore",
// 		TLSCertPath:  "crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
// 		PeerEndpoint: "localhost:7051",
// 		GatewayPeer:  "localhost:7051",
// 	}
// 	if err := setup.Connect(); err != nil {
// 		fmt.Println("Failed to connect to Gateway: ", err)
// 		return
// 	}
// 	contract, err := setup.GetContract("mychaincode")
// 	if err != nil {
// 		fmt.Println("Failed to get contract: ", err)
// 		return
// 	}
// 	// Now you can use the contract to submit transactions and evaluate queries
// }
