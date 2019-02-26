package guardian

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// New returns a new backend as an interface. This func
// is only necessary for builtin backend plugins.
func New() (interface{}, error) {
	return Backend(), nil
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend()
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help:   "",
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"}
		},
		Paths:  framework.PathAppend([]*framework.Path{
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
		}),
		Secrets:      []*framework.Secret{},
		BackendType:  logical.TypeLogical,
	}
	return &b
}

type backend struct {
	*framework.Backend
}

func (b *backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}
