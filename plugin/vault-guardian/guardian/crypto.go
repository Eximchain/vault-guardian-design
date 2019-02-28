package guardian

import (
	"encoding/hex"

	"github.com/eximchain/go-ethereum/crypto"
)

// CreateKey : Generates a secp256k1 key, returns its hex representation & corresponding address
func CreateKey() (privKeyHex, pubAddress string, err error) {
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return "", "", err
	}
	privKeyBinary := crypto.FromECDSA(privKey)
	privKeyHex = hex.EncodeToString(privKeyBinary)
	pubAddress = crypto.PubkeyToAddress(privKey.PublicKey).Hex()
	return
}

// SignWithHexKey : Given bytes to sign and the hex representation of a private key, loads the key and returns the signature
func SignWithHexKey(hash []byte, privKeyHex string) (sig []byte, err error) {
	privKey, loadErr := crypto.HexToECDSA(privKeyHex)
	if loadErr != nil {
		return nil, loadErr
	}
	sig, signErr := crypto.Sign(hash, privKey)
	if signErr != nil {
		return nil, signErr
	}
	return sig, nil
}

// AddressFromHexKey : Given a private key as a hex string, return its corresponding hex address
func AddressFromHexKey(privKeyHex string) (pubAddressHex string, err error) {
	privKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "", err
	}
	pubAddressHex = crypto.PubkeyToAddress(privKey.PublicKey).Hex()
	return
}
