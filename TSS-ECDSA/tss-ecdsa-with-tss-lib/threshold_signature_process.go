package main

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func makePartyIDs(ids []string) []*tss.PartyID {
	parties := make([]*tss.PartyID, len(ids))
	for i, id := range ids {
		parties[i] = tss.NewPartyID(id, "", new(big.Int).SetInt64(int64(i+1)))
	}
	return parties
}

func saveKeyToFile(filename string, data *keygen.LocalPartySaveData) {
	keyBytes := common.ObjectToBytes(data)
	err := ioutil.WriteFile(filename, keyBytes, 0644)
	if err != nil {
		fmt.Println("Error saving key to file:", err)
	}
}
func main() {
	ids := []string{"party1", "party2", "party3"}
	threshold := 2
	parties := tss.SortPartyIDs(makePartyIDs(ids))
	partyIDMap := make(map[string]*tss.PartyID)
	for _, id := range parties {
		partyIDMap[id.Id] = id
	}
	preParams, _ := keygen.GeneratePreParams(1 * time.Minute)
	keygenOutChs := make([]chan tss.Message, len(parties))
	keygenEndChs := make([]chan *keygen.LocalPartySaveData, len(parties))
	for i := 0; i < len(parties); i++ {
		params := tss.NewParameters(tss.Edwards(), tss.NewPeerContext(parties), parties[i], len(parties), threshold)
		party := keygen.NewLocalParty(params, keygenOutChs[i], keygenEndChs[i], preParams)
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				fmt.Println("Error:", err)
				return
			}
		}(party)
	}
	keygenSaveData := make([]*keygen.LocalPartySaveData, len(parties))
	for i := 0; i < len(parties); i++ {
		keygenSaveData[i] = <-keygenEndChs[i]
		saveKeyToFile(fmt.Sprintf("party%d_key.txt", i+1), keygenSaveData[i])
	}
}
func main() {
	// חלק ראשון
	// ...

	// הודעה לחתימה
	msg := new(big.Int).SetInt64(12345)
	signingOutChs := make([]chan tss.Message, len(parties))
	signingEndChs := make([]chan *common.SignatureData, len(parties))
	for i := 0; i < len(parties); i++ {
		params := tss.NewParameters(tss.Edwards(), tss.NewPeerContext(parties), parties[i], len(parties), threshold)
		party := signing.NewLocalParty(msg, params, *keygenSaveData[i], signingOutChs[i], signingEndChs[i])
		go func(p tss.Party) {
			if err := p.Start(); err != nil {
				fmt.Println("Error:", err)
				return
			}
		}(party)
	}
	signatureData := <-signingEndChs
	fmt.Println("Signed Message:", signatureData)
}
