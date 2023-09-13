package bls

import (
	chiaBLS "github.com/chuwt/chia-bls-go"
)

func NewAugMessage(message []byte) *AugMessage {
	return &AugMessage{
		policy:  &Policy{},
		message: message,
		asm:     new(chiaBLS.AugSchemeMPL),
	}
}

func NewAugMessageWithPolicy(message []byte, policy *Policy) *AugMessage {
	return &AugMessage{
		policy:  policy,
		message: message,
		asm:     new(chiaBLS.AugSchemeMPL),
	}
}

func (am AugMessage) Policy() *Policy {
	return am.policy
}

func (am *AugMessage) sign(kp *KeyPair) ([]byte, error) {
	rJSON, err := am.policy.ToJSON()
	if err != nil {
		return nil, err
	}
	msg := append(rJSON, am.message...)
	sig := am.asm.Sign(kp.secretKey, msg)
	am.signatures = append(am.signatures, sig)
	return sig, nil
}

func (am *AugMessage) Sign(kps ...*KeyPair) error {
	for _, k := range kps {
		if _, err := am.sign(k); err != nil {
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

func (am *AugMessage) AggregateVerify(aggSig []byte, pks ...[]byte) (bool, error) {
	if err := am.policy.Validate(pks...); err != nil {
		return false, err
	}

	rJSON, err := am.policy.ToJSON()
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
