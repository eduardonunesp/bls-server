package bls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var mnemonic1 = "" +
	"media spike luggage ramp famous gentle social wolf sing raven student involve " +
	"poverty team capital inspire lumber hat park nose effort still fatigue supply"

func TestNewKeyPair(t *testing.T) {
	kp := NewKeyPair()
	require.NotNil(t, kp)
	require.Len(t, kp.GetPublicKey(), 48)
}

func TestNewKeyPairFromMnemonic(t *testing.T) {
	kp := NewKeyPairFromMnemonic(mnemonic1, "")
	require.NotNil(t, kp)
	require.Len(t, kp.GetPublicKey(), 48)
}

func TestNewKeyPairFromMnemonicWithPassword(t *testing.T) {
	kp := NewKeyPairFromMnemonic(mnemonic1, "password")
	require.NotNil(t, kp)
	require.Len(t, kp.GetPublicKey(), 48)
}
