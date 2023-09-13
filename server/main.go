package main

import (
	"fmt"
	"log"

	"github.com/eduardonunesp/bls-server/commons/bls"
)

var userMnemonic = "" +
	"media spike luggage ramp famous gentle social wolf sing raven student involve " +
	"poverty team capital inspire lumber hat park nose effort still fatigue supply"

var mpcMnemonic = "" +
	"media spike luggage ramp famous gentle social wolf sing raven student involve " +
	"poverty team capital inspire supply hat park nose effort still fatigue lumber"

func main() {
	user := bls.NewKeyPairFromMnemonic(userMnemonic, "")
	mpc := bls.NewKeyPairFromMnemonic(mpcMnemonic, "")

	agm := bls.NewAugMessageWithPolicy(
		[]byte("some message"),
		bls.NewPolicy(
			bls.WithMinSignatures(2),
			bls.WithRequiredSignatures(user.GetPublicKey()),
		),
	)

	if err := agm.Sign(user, mpc); err != nil {
		log.Fatal(err)
	}

	aggSign, err := agm.Aggregate()
	if err != nil {
		log.Fatal(err)
	}

	bs, err := agm.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	agm2, err := bls.Unserialize(bs)
	if err != nil {
		log.Fatal(err)
	}

	result, err := agm2.AggregateVerify(
		aggSign,
		user.GetPublicKey(),
		mpc.GetPublicKey(),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)

}
