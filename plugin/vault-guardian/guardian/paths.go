package guardian

import (
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func paths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "login",
			Fields: map[string]*framework.FieldSchema{
				"okta_username": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "Username of Okta account to login, probably an email address."
				},
				"okta_password": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "Password for associated Okta account."
				},
			}
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathLogin
			}
		},
		&framework.Path{
			Pattern: "sign",
			Fields: map[string]*framework.FieldSchema{
				"raw_data": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "Raw hashed transaction data to sign, do not include the initial 0x."
				},
				"get_fresh_token": &framework.FieldSchema{
					Type: framework.TypeBool,
					Description: "Set true to also get a 'fresh_client_token' with your signed data, allowing one more call to sign.",
					Default: false
				},
				"address_index": &framework.FieldSchema{
					Type: framework.TypeInt,
					Description: "Integer index of which generated address to use.",
					Default: 0
				}
			}
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSign,
				logical.ReadOperation: b.pathGetAddress
			}
		},
		&framework.Path{
			Pattern: "authorize",
			Fields: map[string]*framework.FieldSchema{
				"secret_id": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: "SecretID of the Guardian AppRole."
				}
			}
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathAuthorize
			}
		}
	}
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Fetch login credentials
	oktaUser := data.get("okta_username")
	oktaPass := data.get("okta_password")

	// Do we have an account for them?
	newUser := !GuardianClient.enduserExists(oktaUser)
	if (newUser){
		// Verify it's a real Okta account
		if (GuardianClient.oktaAccountExists(oktaUser)){
			pubAddress, createErr := GuardianClient.createEnduser(oktaUser)
			if createErr != nil {
				return nil, createErr
			}
		} else {
			// Throw a useful error
		}
	}

	// Perform the actual login call, get client_token
	client_token := GuardianClient.loginEnduser(oktaUser, oktaPass)

	if (newUser) {
		respData := map[string]interface{}{
			"client_token" : client_token,
			"address"	   : pubAddress
		}
	} else {
		respData := map[string]interface{}{
			"client_token" : client_token
		}
	}
	return &logical.Response{
		Data: respData
	}
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawDataBytes  := hex.DecodeString(data.get("raw_data").(string))
	privKeyHex 	  := GuardianClient.readKeyHexByToken(req.client_token)
	sigBytes, err := SignWithHexKey(hash, privKeyHex)
	sigHex := hex.EncodeToString(sigBytes)
	return &logical.Response{
		Data: map[string]interface{}{
			"signature" : "0x"+sigHex,
			"fresh_client_token" : "TODO: Placeholder"
		}
	}
}

func (b *backend) pathGetAddress(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	privKeyHex := GuardianClient.readKeyHexByToken(req.ClientToken)
	pubAddress := AddressFromHexKey(privKeyHex)
	return &logical.Response{
		Data: map[string]interface{}{
			"public_address" : pubAddress
		}
	}
}

func (b *backend) pathAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secret_id := data.get("secret_id").(string)
	success := GuardianClient.authorize(secret_id)
	return &logical.Response{
		Data: map[string]interface{}{
			"success" : success
		}
	}
}
