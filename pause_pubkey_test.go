package CPAN

import (
	"testing"
)

func TestPAUSEPublicKey(t *testing.T) {
	if PAUSEPublicKey.KeyIdShortString() != "450F89EC" {
		t.Errorf("Invalid PAUSE public key: %s", PAUSEPublicKey.KeyIdShortString())
	}
	if PAUSEPublicKey.KeyIdString() != "328DA867450F89EC" {
		t.Errorf("Invalid PAUSE public key: %s", PAUSEPublicKey.KeyIdString())
	}
}
