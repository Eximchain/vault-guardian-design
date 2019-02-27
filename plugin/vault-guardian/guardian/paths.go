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

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Fetch login credentials
	oktaUser := data.get("okta_username")
	oktaPass := data.get("okta_password")

	cfg, err := b.Config()
	client := cfg.Client()

	// Do we have an account for them?
	newUser := !client.enduserExists(oktaUser)
	if (newUser){
		// Verify it's a real Okta account
		if (&gc.oktaAccountExists(oktaUser)){
			pubAddress, createErr := client.createEnduser(oktaUser)
			if createErr != nil {
				return nil, createErr
			}
		} else {
			// Throw a useful error
		}
	}

	// Perform the actual login call, get client_token
	client_token := client.loginEnduser(oktaUser, oktaPass)

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

func (b *backend) pathAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	isCreate := req.Operation == logical.CreateOperation

	secret_id, ok := data.GetOk("secret_id").(string)
	if ok {
		cfg, loadCfgErr := b.Config(ctx, req.Storage)
		if loadCfgErr != nil {
			return nil, loadCfgErr
		}
		client, makeClientErr := cfg.Client()
		if makeClientErr != nil {
			return nil makeClientErr
		}
		guardianToken := client.tokenFromSecretID(secret_id)
		cfg.guardianToken = guardianToken
	}
	if cfg.guardianToken == "" {
		return logical.ErrorResponse("secret_id was missing, could not get a guardianToken"), nil
	}
	
	okta_url, ok := data.GetOk("okta_url").(string)
	if ok {
		cfg.oktaUrl = okta_url
	}
	if cfg.oktaUrl == "" {
		return logical.ErrorResponse("Must provide an okta_url")
	}
	
	okta_token, ok := data.GetOk("okta_token").(string)
	if ok {
		cfg.oktaToken = okta_token
	}
	if cfg.oktaToken == "" {
		return logical.ErrorResponse("Must provide an okta_token")
	}
	
	jsonCfg, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonCfg); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"success" : success
		}
	}
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawDataBytes  := hex.DecodeString(data.get("raw_data").(string))
	
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	client, err := cfg.Client()
	privKeyHex 	  := client.readKeyHexByToken(req.ClientToken)

	sigBytes, err := SignWithHexKey(hash, privKeyHex)
	sigHex := hex.EncodeToString(sigBytes)
	return &logical.Response{
		Data: map[string]interface{}{
			"signature" : "0x"+sigHex
		}
	}
}

func (b *backend) pathGetAddress(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	client, err := cfg.Client()
	privKeyHex := client.readKeyHexByToken(req.ClientToken)
	pubAddress := AddressFromHexKey(privKeyHex)
	return &logical.Response{
		Data: map[string]interface{}{
			"public_address" : pubAddress
		}
	}
}
