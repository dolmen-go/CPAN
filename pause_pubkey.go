// Code generated by go run -tags generate pause_pubkey_gen.go # DO NOT EDIT.

package CPAN

import (
	"crypto/dsa"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

// PAUSEPublicKey is the embeded public key of the central PAUSE indexer
var PAUSEPublicKey *packet.PublicKey

func init() {
	var dsaPubKey dsa.PublicKey
	dsaPubKey.P, _ = new(big.Int).SetString("b1381c98d1224106e26816b1f6868a91167cb8db7818e95de3ab5b9380663f3cf6b13fe4aaaf7473c4f72de2f25cb28a38f29c01b0c1cbad67ce46adbacdbe9e2a098cabf090a368336916de4710a2de47b82819ae691122e918da65253de32001b439aca5406ba5857ccdf64cbf964842583d5b54eeeba045394aeb35e0e92b", 16)
	dsaPubKey.Q, _ = new(big.Int).SetString("a2c0a9f5db4d00c847933c6cf14247e62dd4cdbd", 16)
	dsaPubKey.G, _ = new(big.Int).SetString("454ba0013cb0e7d45ea8dcdfcaf1887b8604548d0bbd088789b31940893064f8cf55f72bab946b09d732873c5ea3da6271203b3ced3329b276dafebab8d4c1c1a7b970d2a55ea7ba51398abc61ce58a4493272ff8d90cd331cadd4729df7e6268f4f460ca6308f068166981b9837cf3180862e4103a1bc24a7c2f77215c6244f", 16)
	dsaPubKey.Y, _ = new(big.Int).SetString("972692c1610963a8963d503349baaf271e12a2587057759ceb0b72ccd05485dcf2ae3ffba073e28120a5e672534f3452a56bf4916c7e9d307b06232f309c63c8e40b534b4ae8350aedb6fdff821453efe38a5eb1a607167f28756bbf73d5822440e4c0ebd6622ca2f7ee73d5909c5bb64e482737f177a4372b5554a2e5bfab64", 16)

	PAUSEPublicKey = packet.NewDSAPublicKey(time.Unix(1044279440, 0), &dsaPubKey)
}
