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
