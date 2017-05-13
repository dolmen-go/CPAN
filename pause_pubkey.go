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
	dsaPubKey.P, _ = new(big.Int).SetString("124447544795201619160803883929457844087805318770101855661524345475535504248802200520244790225854354935300406573651704761190130914533244730111603880382642039040909667990384374832425243707691543296567639084605785707017488801505193384009406983827157679058405845599868940273991602093442819137852235602999789021483", 10)
	dsaPubKey.Q, _ = new(big.Int).SetString("929153053588582999483338687968034914788841934269", 10)
	dsaPubKey.G, _ = new(big.Int).SetString("48660891893715863156223077760649025219002151207847476887648785062137049962952102840722200649544969890096714065877360626877113143235501278332853015516829830879140386994947776638938925592704360546265577585647471349706321319684079623668600916059871889372965893643833476300010566217669497192181961629818801235023", 10)
	dsaPubKey.Y, _ = new(big.Int).SetString("106141614855553768519958610793384401187046660405741285871773773800001068026832926789173056702484068419264233846301091742777413343576157404714435357443101597679142112298059460233987591710272570158565583835062796222167318447627916163780957201707103172163542893264769909823654949738341125585418108380212786867044", 10)

	PAUSEPublicKey = packet.NewDSAPublicKey(time.Unix(1044279440, 0), &dsaPubKey)
}