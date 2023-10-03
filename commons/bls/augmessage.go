package bls

import (
	"fmt"

	chiaBLS "github.com/chuwt/chia-bls-go"
	"github.com/eduardonunesp/bls-server/commons/proto"
	protobuf "google.golang.org/protobuf/proto"
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

func Unserialize(data []byte) (*AugMessage, error) {
	var am proto.AugMessage
	if err := protobuf.Unmarshal(data, &am); err != nil {
		return nil, err
	}

	var accounts = make([][]byte, len(am.Policy.RequiredAccounts))
	for i, a := range am.Policy.RequiredAccounts {
		accounts[i] = a.PublicKey
	}

	return &AugMessage{
		policy: &Policy{
			MinAccounts:      int(am.Policy.MinAccounts),
			RequiredAccounts: accounts,
		},
		message:    am.Msg,
		signatures: am.Signatures,
		asm:        new(chiaBLS.AugSchemeMPL),
	}, nil
}

func (am AugMessage) String() string {
	return fmt.Sprintf("AugMessage{policy: %+v, message: %+v, signatures: %s}", am.policy, am.message, am.signatures)
}

func (am AugMessage) Policy() *Policy {
	return am.policy
}

func (am *AugMessage) sign(kp *KeyPair) ([]byte, error) {
	bs, err := am.policy.Serialize()
	if err != nil {
		return nil, err
	}
	msg := append(bs, am.message...)
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

	bs, err := am.policy.Serialize()
	if err != nil {
		return false, err
	}

	msgs := make([][]byte, len(am.signatures))
	for i := range msgs {
		msg := append(bs, am.message...)
		msgs[i] = msg
	}

	return am.asm.AggregateVerify(
		pks,
		msgs,
		aggSig,
	), nil
}

func (am *AugMessage) Serialize() ([]byte, error) {
	accounts := make([]*proto.Account, len(am.policy.RequiredAccounts))
	for i, pk := range am.policy.RequiredAccounts {
		accounts[i] = &proto.Account{
			PublicKey: pk,
		}
	}

	return protobuf.Marshal(&proto.AugMessage{
		Policy: &proto.Policy{
			MinAccounts:      int32(am.policy.MinAccounts),
			RequiredAccounts: accounts,
		},
		Msg:        am.message,
		Signatures: am.signatures,
	})
}
