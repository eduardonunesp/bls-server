package crypto

import (
	"encoding/hex"
	"fmt"

	bls "github.com/chuwt/chia-bls-go"
)

func NewAugMessage(message []byte) *AugMessage {
	return &AugMessage{
		rules:   &Rules{},
		message: message,
		asm:     new(bls.AugSchemeMPL),
	}
}

func NewAugMessageWithRules(message []byte, rules *Rules) *AugMessage {
	return &AugMessage{
		rules:   rules,
		message: message,
		asm:     new(bls.AugSchemeMPL),
	}
}

func (am AugMessage) GetRules() *Rules {
	return am.rules
}

func (am *AugMessage) Sign(kp *KeyPair) ([]byte, error) {
	rJSON, err := am.rules.ToJSON()
	if err != nil {
		return nil, err
	}
	msg := append(rJSON, am.message...)
	sig := am.asm.Sign(kp.secretKey, msg)
	am.signatures = append(am.signatures, sig)
	return sig, nil
}

func (am *AugMessage) MultiSign(kps ...*KeyPair) error {
	for _, k := range kps {
		if _, err := am.Sign(k); err != nil {
			return err
		}
	}

	return nil
}

func (am *AugMessage) Verify(kp *KeyPair, sig []byte) bool {
	return am.asm.Verify(kp.secretKey.GetPublicKey(), am.message, sig)
}

func (am *AugMessage) Aggregate() ([]byte, error) {
	return am.asm.Aggregate(am.signatures...)
}

func (am *AugMessage) testRules(pks ...[]byte) error {
	if len(pks) != len(am.signatures) {
		return ErrMinSignaturesNotMet
	}

	if len(am.rules.RequiredSignatures) > 0 {
		found := false
		for _, pk := range pks {
			pk := fmt.Sprintf("0x%s", hex.EncodeToString(pk))
			for _, sig := range am.rules.RequiredSignatures {
				if pk == sig {
					found = true
				}
			}
		}

		if !found {
			return ErrRequiredSignaturesNotMet
		}
	}

	if len(am.rules.OptionalSignatures) > 1 {
		found := false
	Exit:
		for _, pk := range pks {
			pk := fmt.Sprintf("0x%s", hex.EncodeToString(pk))
			for _, sig := range am.rules.OptionalSignatures {
				if pk == sig {
					found = true
					continue Exit
				}
			}
		}

		if !found {
			return ErrRequiredSignaturesNotMet
		}
	}

	return nil
}

func (am *AugMessage) AggregateVerify(aggSig []byte, pks ...[]byte) (bool, error) {
	if err := am.testRules(pks...); err != nil {
		return false, err
	}

	rJSON, err := am.rules.ToJSON()
	if err != nil {
		return false, err
	}

	msgs := make([][]byte, len(am.signatures))
	for i := range msgs {
		msg := append(rJSON, am.message...)
		msgs[i] = msg
	}

	return am.asm.AggregateVerify(
		pks,
		msgs,
		aggSig,
	), nil
}
