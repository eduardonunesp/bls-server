package bls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicies(t *testing.T) {
	tests := []struct {
		name string
		p    *Policy
		pks  [][]byte
	}{
		{
			name: "Test default policy",
			p:    NewPolicy(),
			pks:  [][]byte{{0x01}, {0x02}, {0x03}},
		},
		{
			name: "Test default policy with 0 pks",
			p:    NewPolicy(),
			pks:  [][]byte{},
		},
		{
			name: "Test default policy with min sig of 1",
			p:    NewPolicy(WithMinAccounts(1)),
			pks:  [][]byte{{0x01}},
		},
		{
			name: "Test default policy with min sig of 2",
			p:    NewPolicy(WithMinAccounts(2)),
			pks:  [][]byte{{0x01}, {0x02}, {0x03}},
		},
		{
			name: "Test default policy with required sig",
			p:    NewPolicy(WithRequiredAccounts([]byte{0x01})),
			pks:  [][]byte{{0x01}, {0x02}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate(tt.pks...)
			require.NoError(t, err)
		})
	}
}
