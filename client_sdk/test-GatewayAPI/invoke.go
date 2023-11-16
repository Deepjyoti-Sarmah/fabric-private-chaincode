// package main

// import (
// 	"fmt"
// 	"net/http"

// 	"github.com/hyperledger/fabric-gateway/pkg/client"
// )

// // Invoke handles chaincode invoke requests.
// func (setup *OrgSetup) Invoke(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("Received Invoke request")
// 	if err := r.ParseForm(); err != nil {
// 		fmt.Fprintf(w, "ParseForm() err: %s", err)
// 		return
// 	}
// 	chainCodeName := r.FormValue("chaincodeid")
// 	channelID := r.FormValue("channelid")
// 	function := r.FormValue("function")
// 	args := r.Form["args"]
// 	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)

// 	// Convert []string slice to [][]byte slice
// 	byteArgs := make([][]byte, len(args))
// 	for i, arg := range args {
// 		byteArgs[i] = []byte(arg)
// 	}

// 	network := setup.Gateway.GetNetwork(channelID)
// 	contract := network.GetContract(chainCodeName)
// 	txn, err := contract.NewTransaction(function, client.WithArguments(byteArgs...))
// 	if err != nil {
// 		fmt.Fprintf(w, "Error creating transaction: %s", err)
// 		return
// 	}
// 	result, err := txn.Submit()
// 	if err != nil {
// 		fmt.Fprintf(w, "Error submitting transaction: %s", err)
// 		return
// 	}
// 	fmt.Fprintf(w, "Transaction ID : %s Response: %s", txn.TransactionID(), result)
// }

