package CPAN

import (
	"testing"
)

func TestPAUSEKeyRing(t *testing.T) {
	if len(PAUSEKeyRing.KeysById(0x328DA867450F89EC)) == 0 {
		t.Error("Invalid PAUSE key ring: key 0x328DA867450F89EC not found")
	}
}
