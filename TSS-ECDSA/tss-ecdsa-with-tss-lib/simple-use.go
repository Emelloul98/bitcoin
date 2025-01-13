package main

import (
	"fmt"
	"io/ioutil"
	"time"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	// Number of parties involved
	n := 3
	// Threshold (minimum number of parties required to sign)
	t := 2

	// Create an array to store party IDs
	parties := make([]*tss.PartyID, n)
	// Array to store private keys of each party
	privKeys := make([]*btcec.PrivateKey, n)

	for i := 0; i < n; i++ {
		// Create a unique private key for each party
		privKey, pubKey := btcec.PrivKeyFromBytes([]byte(fmt.Sprintf("unique_key_%d", i)))
		pubKeyECDSA := pubKey.ToECDSA()

		// Store the private key in the array
		privKeys[i] = privKey

		// Convert the X coordinate of the public key to *big.Int
		X := new(big.Int).SetBytes(pubKeyECDSA.X.Bytes())

		// Create a unique Party ID for each party
		parties[i] = tss.NewPartyID(
			fmt.Sprintf("party-%d", i),  // id
			fmt.Sprintf("Party %d", i),  // moniker
			X,                           // X coordinate as *big.Int
		)
	}

	// Sort the party IDs
	sortedParties := tss.SortPartyIDs(parties)

	// Create a peer context for the parties
	ctx := tss.NewPeerContext(sortedParties)

	// Choose an elliptic curve (secp256k1)
	curve := tss.S256()

	// Set up parameters for key generation
	params := tss.NewParameters(curve, ctx, sortedParties[0], len(sortedParties), t)

	// Communication channels
	outCh := make(chan tss.Message, n*n)
	endCh := make(chan *keygen.LocalPartySaveData, n)

	// Pre-computation (optional, but recommended)
	preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil {
		fmt.Printf("Error generating preParams: %v\n", err)
		return
	}

	// Check if preParams is nil
	if preParams == nil {
		fmt.Println("PreParams is nil, aborting key generation")
		return
	}

	// Create local parties for key generation
	localParties := make([]*keygen.LocalParty, n)
	for i := 0; i < n; i++ {
		localParties[i] = keygen.NewLocalParty(
			params,
			outCh,
			endCh,
			*preParams,  // Dereference preParams
		).(*keygen.LocalParty) // Type assertion
	}

	// Save each party's private key to a separate file
	for i, privKey := range privKeys {
		// Convert the private key to a file
		fileName := fmt.Sprintf("party_%d_private_key.pem", i)
		err := ioutil.WriteFile(fileName, privKey.Serialize(), 0644)
		if err != nil {
			fmt.Printf("Error writing private key to file: %v\n", err)
			return
		}
		fmt.Printf("Private key of Party %d saved to %s\n", i, fileName)
	}

	fmt.Println("Key generation successful!")
}
