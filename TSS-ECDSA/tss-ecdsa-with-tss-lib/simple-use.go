package main

import (
	"flag"
	"log"
	"time"

	"github.com/fatih/color"
	"github.com/keep-network/tss-lib/tss"
	"github.com/keep-network/tss-lib/ecdsa/keygen"
)

func main() {
	// Parsing command-line flags
	n := flag.Int("n", 3, "Number of participants")
	t := flag.Int("t", 2, "Threshold for signing")
	flag.Parse()

	success := color.New(color.FgGreen).SprintFunc()
	errorColor := color.New(color.FgRed).SprintFunc()

	log.Println(success("Starting key generation process..."))

	params, preParams := setupKeygen(*n, *t)
	createParties(*n, params, preParams)

	log.Println(success("Test completed successfully!"))
}

// setupKeygen initializes key generation parameters.
// n: number of participants
// t: signing threshold
func setupKeygen(n, t int) (*tss.Parameters, *keygen.LocalPreParams) {
	// Generate party IDs and context
	parties := tss.GenerateTestPartyIDs(n)
	sortedParties := tss.SortPartyIDs(parties)
	ctx := tss.NewPeerContext(sortedParties)
	params := tss.NewParameters(tss.S256(), ctx, sortedParties[0], n, t)

	// Generate pre-parameters
	preParams, err := keygen.GeneratePreParams(1 * time.Minute)
	if err != nil || preParams == nil {
		log.Fatalf("Error generating preParams: %v", err)
	}

	if !preParams.Validate() {
		log.Fatal("PreParams validation failed!")
	}

	return params, preParams
}

// createParties initializes the local parties for key generation.
func createParties(n int, params *tss.Parameters, preParams *keygen.LocalPreParams) {
	outCh := make(chan tss.Message, n*n)
	endCh := make(chan *keygen.LocalPartySaveData, n)

	for i := 0; i < n; i++ {
		party := keygen.NewLocalParty(params, outCh, endCh, *preParams)
		log.Printf("Party %d created successfully: %v\n", i, party)
	}
}
