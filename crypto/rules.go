package crypto

import "encoding/json"

type RulesOption func(*Rules)

func NewRules(rulesOptions ...RulesOption) *Rules {
	rls := &Rules{
		MinSignatures:      0,
		RequiredSignatures: make([]string, 0),
		OptionalSignatures: make([]string, 0),
	}

	for _, opt := range rulesOptions {
		opt(rls)
	}

	return rls
}

func WithMinSignatures(min int) RulesOption {
	return func(r *Rules) {
		r.MinSignatures = min
	}
}

func WithRequiredSignatures(pks ...string) RulesOption {
	return func(r *Rules) {
		r.RequiredSignatures = pks
	}
}

func WithOptionalSignatures(pks ...string) RulesOption {
	return func(r *Rules) {
		r.OptionalSignatures = pks
	}
}

func RulesFromJSON(data []byte) (*Rules, error) {
	var r *Rules
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rules) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}
