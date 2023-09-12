package main

import (
	"fmt"
	"log"

	"github.com/eduardonunesp/bls-server/crypto"
)

var mnemonic1 = "" +
	"media spike luggage ramp famous gentle social wolf sing raven student involve " +
	"poverty team capital inspire lumber hat park nose effort still fatigue supply"

var mnemonic2 = "" +
	"media spike luggage ramp famous gentle social wolf sing raven student involve " +
	"poverty team capital inspire supply hat park nose effort still fatigue lumber"

func main() {
	kp1 := crypto.NewKeyPairFromMnemonic(mnemonic1, "")
	kp2 := crypto.NewKeyPairFromMnemonic(mnemonic2, "")

	agm := crypto.NewAugMessageWithRules(
		[]byte("hello1"),
		crypto.NewRules(
			crypto.WithMinSignatures(2),
			crypto.WithRequiredSignatures(kp1.GetHexPublicKey()),
		),
	)

	if err := agm.MultiSign(kp1, kp2); err != nil {
		log.Fatal(err)
	}

	aggSign, err := agm.Aggregate()
	if err != nil {
		log.Fatal(err)
	}

	result, err := agm.AggregateVerify(aggSign, kp1.GetPublicKey(), kp2.GetPublicKey())
	if err != nil {
		log.Fatal(err)
	}
	log.Println(result)

	r, _ := agm.GetRules().ToJSON()
	fmt.Println(string(r))
}
