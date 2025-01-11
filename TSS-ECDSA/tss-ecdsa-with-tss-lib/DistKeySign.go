package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// Function to generate distributed key shares
//export GenerateKeyShares
func GenerateKeyShares(parties C.int, threshold C.int, prefix *C.char) C.int {
	numParties := int(parties)
	thresholdValue := int(threshold)
	filePrefix := C.GoString(prefix)

	if numParties < thresholdValue {
		fmt.Println("Error: number of parties must be >= threshold")
		return -1
	}

	// Create TSS parameters
	partyIDList := tss.GenerateTestPartyIDs(numParties)
	ctx := tss.NewPeerContext(partyIDList)
	params := tss.NewParameters(tss.S256(), ctx, partyIDList[0], numParties, thresholdValue)

	preParams, err := keygen.GeneratePreParams(2 * time.Minute)
	if err != nil {
		fmt.Printf("Error generating preParams: %v\n", err)
		return -2
	}

	// Channels for messages and save data
	messageChan := make(chan tss.Message, numParties)
	saveDataChan := make(chan keygen.LocalPartySaveData, numParties)

	// Start key generation for all parties
	for i := 0; i < numParties; i++ {
		party := keygen.NewLocalParty(params, messageChan, saveDataChan, *preParams)
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				fmt.Printf("Error starting party %d: %v\n", i, err)
			}
		}(party)
	}

	// Collect save data for each party
	keys := make([]keygen.LocalPartySaveData, numParties)
	for i := 0; i < numParties; i++ {
		keys[i] = <-saveDataChan
	}

	// Save key shares to files
	for i, key := range keys {
		fileName := fmt.Sprintf("%s_party_%d.json", filePrefix, i)
		file, err := os.Create(fileName)
		if err != nil {
			fmt.Printf("Failed to create file for party %d: %v\n", i, err)
			return -3
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		if err := encoder.Encode(key); err != nil {
			fmt.Printf("Failed to save key for party %d: %v\n", i, err)
			return -4
		}
	}

	return 0 // Success
}

// Function to sign a message using distributed key shares
//export SignMessageWithKeyShares
func SignMessageWithKeyShares(message *C.char, numParties C.int, threshold C.int, prefix *C.char) C.int {
	msg := C.GoString(message)
	numPartiesInt := int(numParties)
	thresholdInt := int(threshold)
	filePrefix := C.GoString(prefix)

	// Convert message to *big.Int
	msgBigInt := new(big.Int).SetBytes([]byte(msg))

	// Load key shares from files
	keys := make([]keygen.LocalPartySaveData, numPartiesInt)
	for i := 0; i < numPartiesInt; i++ {
		fileName := fmt.Sprintf("%s_party_%d.json", filePrefix, i)
		file, err := os.Open(fileName)
		if err != nil {
			fmt.Printf("Failed to open file for party %d: %v\n", i, err)
			return -1
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&keys[i]); err != nil {
			fmt.Printf("Failed to load key for party %d: %v\n", i, err)
			return -2
		}
	}

	// Initialize TSS parameters
	partyIDList := tss.GenerateTestPartyIDs(numPartiesInt)
	ctx := tss.NewPeerContext(partyIDList)
	params := tss.NewParameters(tss.S256(), ctx, partyIDList[0], numPartiesInt, thresholdInt)

	// Channels for signing process
	messageChan := make(chan tss.Message, numPartiesInt)
	signatureDataChan := make(chan signing.SignatureData, numPartiesInt)

	// Start signing for each party
	for i := 0; i < numPartiesInt; i++ {
		party := signing.NewLocalParty(msgBigInt, params, keys[i], messageChan, signatureDataChan)
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				fmt.Printf("Error starting signing for party: %v\n", err)
			}
		}(party)
	}

	// Collect signature data
	var finalSignature signing.SignatureData
	for i := 0; i < thresholdInt; i++ {
		partialSig := <-signatureDataChan
		finalSignature = partialSig
	}

	// Print final signature
	fmt.Printf("Generated signature: R = %x, S = %x\n", finalSignature.R, finalSignature.S)
	return 0
}

func main() {
	parties := C.int(3)
	threshold := C.int(2)
	prefix := C.CString("keygen")

	// Generate distributed key shares
	result := GenerateKeyShares(parties, threshold, prefix)
	if result != 0 {
		fmt.Printf("GenerateKeyShares failed with error code: %d\n", result)
		return
	}

	// Sign a message
	message := C.CString("Hello, TSS!")
	result = SignMessageWithKeyShares(message, parties, threshold, prefix)
	if result != 0 {
		fmt.Printf("SignMessageWithKeyShares failed with error code: %d\n", result)
	}
}

