package main

import (
	"fmt"
	"time"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)
func main() {
	// Total number of participants (n) and threshold (t) for signing
	n, t := 3, 2

	// Generate unique PartyIDs for the participants. Each party has a unique identifier.
	parties := tss.GenerateTestPartyIDs(n)

	// Sort the PartyIDs to ensure they are in a defined order.
	sortedParties := tss.SortPartyIDs(parties)

	// Create a new context for the parties involved in the multi-party computation.
	ctx := tss.NewPeerContext(sortedParties)

	// Create parameters for the cryptographic process (key generation)
	params := tss.NewParameters(tss.S256(), ctx, sortedParties[0], n, t)

	// Generate pre-computation parameters. These are optional but recommended for efficient key generation.
	preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil || preParams == nil {
		// If there was an error generating preParams, print the error message and exit.
		// If preParams is nil, it indicates that something went wrong during pre-computation.
		fmt.Println("Error generating preParams:", err)
		return
	}

	// Channels for communication between the parties during the key generation process.
	// `outCh` is used for sending messages, and `endCh` is used for receiving the final save data.
	outCh := make(chan tss.Message, n*n)
	endCh := make(chan *keygen.LocalPartySaveData, n)

	// Create local parties for each participant in the key generation process.
	for i := 0; i < n; i++ {
		party := keygen.NewLocalParty(params, outCh, endCh, *preParams)
		// For testing purposes, print the created party information.
		// This indicates that the party has been created successfully with its assigned parameters.
		fmt.Printf("Party %d created successfully: %v\n", i, party)
	}

	// Print a success message indicating that the test has completed without issues.
	fmt.Println("Test completed successfully!")
}
