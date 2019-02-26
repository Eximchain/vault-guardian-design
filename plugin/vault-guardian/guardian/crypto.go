package guardian

import (
	"encoding/hex"

	"github.com/eximchain/go-ethereum/crypto"
)

func CreateKey() (privKeyHex, pubAddressHex string) {
	privKey, err := crypto.GenerateKey()
	privKeyBinary := crypto.FromECDSA(privKey)
	privKeyHex := hex.EncodeToString(privKeyBinary)
	pubAddress := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
}

func SignWithHexKey(hash []byte, privKeyHex string) (sig []byte, err error) {
	privKey, loadErr := crypto.HexToECDSA(privKeyHex)
	sig, signErr := crypto.Sign(hash, privKey)
	return sig, nil
}

func AddressFromHexKey(privKeyHex string) (pubAddressHex string) {
	privKey, loadErr := crypto.HexToECDSA(privKeyHex)
	pubAddressHex := crypto.PubkeyToAddress(privKey.PublicKey).Hex()
}
