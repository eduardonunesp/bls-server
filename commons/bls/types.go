package bls

import (
	"errors"

	bls "github.com/chuwt/chia-bls-go"
)

var (
	ErrKeyPairAlreadyGenerated  = errors.New("key pair already generated")
	ErrMinSignaturesNotMet      = errors.New("min signatures not met")
	ErrRequiredSignaturesNotMet = errors.New("required signatures not met")
	ErrOptionalSignaturesNotMet = errors.New("optional signatures not met")
)

type Policy struct {
	MinSignatures      int      `json:"min_signatures"`
	OptionalSignatures []string `json:"optional_signatures"`
	RequiredSignatures []string `json:"required_signatures"`
}

type KeyPair struct {
	secretKey bls.PrivateKey
}

type AugMessage struct {
	policy     *Policy
	message    []byte
	signatures [][]byte
	asm        *bls.AugSchemeMPL
}
