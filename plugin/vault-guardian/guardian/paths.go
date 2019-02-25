package guardian

import (
	"context"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

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
	return &logical.Response{
		Data: map[string]interface{}{
			"client_token" : "TODO: Placeholder"
		}
	}
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"signature" : "TODO: Placeholder",
			"fresh_client_token" : "TODO: Placeholder"
		}
	}
}

func (b *backend) pathGetAddress(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"public_address" : "TODO: Placeholder"
		}
	}
}

func (b *backend) pathAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"success" : "TODO: Make a boolean"
		}
	}
}
