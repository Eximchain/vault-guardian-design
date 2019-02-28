package guardian

import (
	"context"
	"encoding/hex"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var configErrResp = logical.ErrorResponse("Error reading Config() from Storage")
var clientErrResp = logical.ErrorResponse("Error building Client from Config")
var tokenErrResp = logical.ErrorResponse("Failed to load key from token")

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Fetch login credentials
	oktaUser := data.Get("okta_username").(string)
	oktaPass := data.Get("okta_password").(string)

	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return configErrResp, err
	}
	client, err := cfg.Client()
	if err != nil {
		return clientErrResp, err
	}

	// Do we have an account for them?
	newUser, checkErr := client.enduserExists(oktaUser)
	if checkErr != nil {
		return nil, checkErr
	}
	pubAddress := ""
	if newUser {
		// Verify it's a real Okta account
		isOktaUser, oktaCheckErr := client.oktaAccountExists(oktaUser)
		if oktaCheckErr != nil {
			return nil, oktaCheckErr
		}
		if isOktaUser {
			var createErr error
			pubAddress, createErr = client.createEnduser(oktaUser)
			if createErr != nil {
				return nil, createErr
			}
		} else {
			// Throw a useful error
		}
	}

	// Perform the actual login call, get client_token
	clientToken, loginErr := client.loginEnduser(oktaUser, oktaPass)
	if loginErr != nil {
		return logical.ErrorResponse("Unable to login with Okta using these credentials"), loginErr
	}

	// This method is prototyped, commenting out while we get core flow working
	// single_sign_token := client.makeSingleSignToken(oktaUser)

	var respData map[string]interface{}
	if newUser {
		respData = map[string]interface{}{
			"client_token": clientToken,
			"address":      pubAddress}
	} else {
		respData = map[string]interface{}{"client_token": clientToken}
	}
	return &logical.Response{Data: respData}, nil
}

func (b *backend) pathAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID, ok := data.GetOk("secret_id")
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return configErrResp, loadCfgErr
	}
	if ok {
		client, makeClientErr := cfg.Client()
		if makeClientErr != nil {
			return clientErrResp, makeClientErr
		}
		guardianToken, tokenErr := client.tokenFromSecretID(secretID.(string))
		if tokenErr != nil {
			return logical.ErrorResponse("Error fetching token using SecretID"), tokenErr
		}
		cfg.guardianToken = guardianToken
	}
	if cfg.guardianToken == "" {
		return logical.ErrorResponse("secret_id was missing, could not get a guardianToken"), nil
	}

	oktaURL, ok := data.GetOk("okta_url")
	if ok {
		cfg.oktaURL = oktaURL.(string)
	}
	if cfg.oktaURL == "" {
		return logical.ErrorResponse("Must provide an okta_url"), nil
	}

	oktaToken, ok := data.GetOk("okta_token")
	if ok {
		cfg.oktaToken = oktaToken.(string)
	}
	if cfg.oktaToken == "" {
		return logical.ErrorResponse("Must provide an okta_token"), nil
	}

	jsonCfg, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return logical.ErrorResponse("Error making a StorageEntryJSON out of the config"), err
	}
	if err := req.Storage.Put(ctx, jsonCfg); err != nil {
		return logical.ErrorResponse("Error saving the config StorageEntry"), err
	}

	return &logical.Response{
		Data: map[string]interface{}{"success": true},
	}, nil
}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rawDataStr := data.Get("raw_data")

	rawDataBytes, decodeErr := hex.DecodeString(rawDataStr.(string))
	if decodeErr != nil {
		return logical.ErrorResponse("Unable to decode raw_data string from hex to bytes"), decodeErr
	}

	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return configErrResp, loadCfgErr
	}
	client, makeClientErr := cfg.Client()
	if makeClientErr != nil {
		return clientErrResp, makeClientErr
	}
	privKeyHex, readKeyErr := client.readKeyHexByToken(req.ClientToken)
	if readKeyErr != nil {
		return tokenErrResp, readKeyErr
	}
	sigBytes, err := SignWithHexKey(rawDataBytes, privKeyHex)
	if err != nil {
		return logical.ErrorResponse("Failed to unmarshall key & sign"), err
	}
	sigHex := hex.EncodeToString(sigBytes)
	return &logical.Response{
		Data: map[string]interface{}{"signature": "0x" + sigHex},
	}, nil
}

func (b *backend) pathGetAddress(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, loadCfgErr := b.Config(ctx, req.Storage)
	if loadCfgErr != nil {
		return configErrResp, loadCfgErr
	}
	client, makeClientErr := cfg.Client()
	if makeClientErr != nil {
		return clientErrResp, makeClientErr
	}
	privKeyHex, readKeyErr := client.readKeyHexByToken(req.ClientToken)
	if readKeyErr != nil {
		return tokenErrResp, readKeyErr
	}
	pubAddress, getAddressErr := AddressFromHexKey(privKeyHex)
	if getAddressErr != nil {
		return logical.ErrorResponse("Fail to derive address from private key"), getAddressErr
	}
	return &logical.Response{
		Data: map[string]interface{}{"public_address": pubAddress},
	}, nil
}
