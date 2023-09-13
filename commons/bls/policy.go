package bls

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type PolicyOption func(*Policy)

func NewPolicy(policyOptions ...PolicyOption) *Policy {
	policy := &Policy{
		MinSignatures:      0,
		RequiredSignatures: make([]string, 0),
	}

	for _, opt := range policyOptions {
		opt(policy)
	}

	return policy
}

func WithMinSignatures(min int) PolicyOption {
	return func(r *Policy) {
		r.MinSignatures = min
	}
}

func WithRequiredSignatures(pks ...string) PolicyOption {
	return func(r *Policy) {
		r.RequiredSignatures = pks
	}
}

func WithOptionalSignatures(pks ...string) PolicyOption {
	return func(r *Policy) {
		r.OptionalSignatures = pks
	}
}

func PolicyFromJSON(data []byte) (*Policy, error) {
	var r *Policy
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Policy) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

func (r *Policy) Validate(pks ...[]byte) error {
	if len(pks) < r.MinSignatures {
		return ErrMinSignaturesNotMet
	}

	if len(r.RequiredSignatures) > 0 {
		found := false
		for _, pk := range pks {
			pk := fmt.Sprintf("0x%s", hex.EncodeToString(pk))
			for _, sig := range r.RequiredSignatures {
				if pk == sig {
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
