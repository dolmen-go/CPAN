package CPAN

import (
	"crypto/dsa"
	"errors"
	//"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func readPubKey(path string) (*packet.PublicKey, error) {
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("not a public key")
	}

	r := packet.NewReader(block.Body)
	pkt, err := r.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}

	return key, nil
}

func TestReadChecksums(t *testing.T) {
	/*
		pubkey, err := readPubKey("testdata/pause.pubkey")
		if err != nil {
			t.Fatal(err)
		}
	*/
	keyring := PAUSEKeyRing
	pubkey := keyring.(openpgp.EntityList)[0].PrimaryKey
	t.Log("Creation time:", pubkey.CreationTime)
	t.Log("Algorithm:", pubkey.PubKeyAlgo)
	if pubkey, ok := pubkey.PublicKey.(*dsa.PublicKey); ok {
		t.Logf("DSA key:\n- Parameters: %#v\n- Y: %v", pubkey.Parameters, pubkey.Y)
	}

	r, err := os.Open("testdata/CHECKSUMS")
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := ReadCheckSums(r, keyring)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", checksums)
}
