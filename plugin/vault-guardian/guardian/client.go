package guardian

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/okta/okta-sdk-golang/okta"
)

//-----------------------------------------
//  Core Configuration
//-----------------------------------------

//
type Client struct {
	vault *api.Client
	okta  *okta.Client
}

// ClientFromConfig : Constructor which takes a Config to produce a Client.
func ClientFromConfig(cfg *Config) (*Client, error) {
	var gc Client

	// Set up Vault client with default token
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, err
	}
	client.SetToken(cfg.guardianToken)
	gc.vault = client

	// Set up Okta client
	oktaConfig := okta.NewConfig().WithOrgUrl(cfg.oktaURL).WithToken(cfg.oktaToken)
	oktaClient := okta.NewClient(oktaConfig, nil, nil)
	gc.okta = oktaClient
	return &gc, nil
}

// Config : Required constants for running Guardian.  guardianToken must hold guardian policy.
type Config struct {
	guardianToken string `json:guardian_token`
	oktaURL       string `json:okta_url`
	oktaToken     string `json:okta_token`
}

// Client : Call on a Config to get a configured Client.
func (cfg *Config) Client() (*Client, error) { return ClientFromConfig(cfg) }

func (gc *Client) pluginAuthorized() (isAuthorized bool) {
	return gc.vault.Token() != ""
}

//-----------------------------------------
//  Token Operations
//-----------------------------------------

func (gc *Client) tokenFromSecretID(secretID string) (clientToken string, err error) {
	authData := map[string]interface{}{
		"role_id":   "guardian-role-id",
		"secret_id": secretID,
	}
	resp, err := gc.vault.Logical().Write("auth/approle/login", authData)
	if err != nil {
		return "", err
	}
	if resp.Auth == nil {
		return "", fmt.Errorf("no auth info returned")
	}
	return resp.Auth.ClientToken, nil
}

type TokenLookupMetadata struct {
	username string
}

func (gc *Client) usernameFromToken(clientToken string) (username string, err error) {
	resp, err := gc.vault.Logical().Write("/auth/token/lookup", map[string]interface{}{
		"token": clientToken,
	})
	if err != nil {
		return "", err
	}
	// TODO: How does this look in errors?  Is Write the correct method?
	tokenMetadata := resp.Data["meta"].(TokenLookupMetadata)
	return tokenMetadata.username, nil
}

func (gc *Client) readKeyHexByToken(clientToken string) (privKeyHex string, err error) {
	username, usernameErr := gc.usernameFromToken(clientToken)
	if usernameErr != nil {
		return "", usernameErr
	}
	resp, err := gc.vault.Logical().Read(fmt.Sprintf("/keys/%s", username))
	if err != nil {
		return "", err
	}
	return resp.Data["privKeyHex"].(string), nil
}

func (gc *Client) makeSingleSignToken(username string) (clientToken string, err error) {
	tokenArg := map[string]interface{}{
		"policies": []string{"enduser"},
		"num_uses": 1,
		"metadata": map[string]string{"username": username}}
	tokenResp, err := gc.vault.Logical().Write("/auth/token/create/guardian-enduser", tokenArg)
	if err != nil {
		return "", err
	}
	return tokenResp.Auth.ClientToken, nil
}

//-----------------------------------------
//  User Management
//-----------------------------------------

func (gc *Client) loginEnduser(username string, password string) (clientToken string, err error) {
	defaultConf := api.DefaultConfig()
	emptyClient, makeClientErr := api.NewClient(defaultConf)
	if makeClientErr != nil {
		return "", makeClientErr
	}
	loginResp, loginErr := emptyClient.Logical().Write(fmt.Sprintf("auth/okta/login/%s", username), map[string]interface{}{
		"password": password,
	})
	if loginErr != nil {
		return "", loginErr
	}
	return loginResp.Auth.ClientToken, nil
}

func (gc *Client) enduserExists(username string) (exists bool, err error) {
	resp, err := gc.vault.Logical().Read(fmt.Sprintf("/auth/okta/users/%s", username))
	if err != nil {
		return false, err
	}
	// Determine what above looks like when no account is registered
	return resp != nil, nil
}

func (gc *Client) createEnduser(username string) (publicAddressHex string, err error) {
	createData := map[string]interface{}{
		"username": username,
		"policies": []string{},
		"groups":   []string{"guardian-enduser"}}
	_, userErr := gc.vault.Logical().Write(fmt.Sprintf("/auth/okta/users/%s", username), createData)
	if userErr != nil {
		return "", userErr
	}
	privKeyHex, publicAddressHex, createKeyErr := CreateKey()
	if createKeyErr != nil {
		return "", createKeyErr
	}
	secretData := map[string]interface{}{
		"privKeyHex":       privKeyHex,
		"publicAddressHex": publicAddressHex}
	_, keyErr := gc.vault.Logical().Write(fmt.Sprintf("/keys/%s", username), secretData)
	if keyErr != nil {
		return "", keyErr
	}
	return publicAddressHex, nil
}

//-----------------------------------------
//  Okta Calls
//-----------------------------------------

func (gc *Client) oktaAccountExists(username string) (exists bool, err error) {
	// Determine what the response looks like for non-existent users
	user, _, err := gc.okta.User.GetUser(username, nil)
	if err != nil {
		return false, err
	}
	return user != nil, nil
}
