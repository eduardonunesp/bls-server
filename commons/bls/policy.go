package bls

import (
	"bytes"
	"encoding/json"

	"github.com/eduardonunesp/bls-server/commons/proto"
	protobuf "google.golang.org/protobuf/proto"
)

type PolicyOption func(*Policy)

func NewPolicy(policyOptions ...PolicyOption) *Policy {
	policy := &Policy{}

	for _, opt := range policyOptions {
		opt(policy)
	}

	return policy
}

func WithMinAccounts(min int) PolicyOption {
	return func(r *Policy) {
		r.MinAccounts = min
	}
}

func WithRequiredAccounts(pks ...[]byte) PolicyOption {
	return func(r *Policy) {
		r.RequiredAccounts = pks
	}
}

func PolicyFromJSON(data []byte) (*Policy, error) {
	var r *Policy
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Policy) Serialize() ([]byte, error) {
	accounts := make([]*proto.Account, len(r.RequiredAccounts))
	for i, pk := range r.RequiredAccounts {
		accounts[i] = &proto.Account{
			PublicKey: pk,
		}
	}

	return protobuf.Marshal(&proto.Policy{
		MinAccounts:      int32(r.MinAccounts),
		RequiredAccounts: accounts,
	})
}

func (r *Policy) Validate(pks ...[]byte) error {
	if len(pks) < r.MinAccounts {
		return ErrMinSignaturesNotMet
	}

	if len(r.RequiredAccounts) > 0 {
		found := false
		for _, pk := range pks {
			for _, sig := range r.RequiredAccounts {
				if bytes.Compare(pk, sig) == 0 {
					found = true
				}
			}
		}

		if !found {
			return ErrRequiredSignaturesNotMet
		}
	}

	return nil
}
