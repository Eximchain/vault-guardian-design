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
	conf := api.DefaultConfig()
	conf.Address = "http://127.0.0.1:8200"
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	client.SetToken(cfg.GuardianToken)
	gc.vault = client

	// Set up Okta client
	oktaConfig := okta.NewConfig().WithOrgUrl(fmt.Sprintf("https://%s.okta.com", cfg.OktaURL)).WithToken(cfg.OktaToken)
	oktaClient := okta.NewClient(oktaConfig, nil, nil)
	gc.okta = oktaClient
	return &gc, nil
}

// Config : Required constants for running Guardian.  guardianToken must hold guardian policy.
type Config struct {
	GuardianToken string `json:"guardian_token"`
	OktaURL       string `json:"okta_url"`
	OktaToken     string `json:"okta_token"`
}

// Client : Call on a Config to get a configured Client.
func (cfg *Config) Client() (*Client, error) {
	return ClientFromConfig(cfg)
}

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
	resp, err := gc.vault.Logical().Write("/auth/approle/login", authData)
	if err != nil {
		return "", err
	}
	if resp.Auth == nil {
		return "", fmt.Errorf("no auth info returned")
	}
	return resp.Auth.ClientToken, nil
}

func (gc *Client) usernameFromEntityID(EntityID string) (username string, err error) {
	resp, err := gc.vault.Logical().Write("/identity/lookup/entity", map[string]interface{}{
		"id": EntityID,
	})
	if err != nil {
		return "", err
	}
	aliases := resp.Data["aliases"].([]interface{})
	alias := aliases[0].(map[string]interface{})
	return alias["name"].(string), nil
}

func (gc *Client) readKeyHexByEntityID(EntityID string) (privKeyHex string, err error) {
	username, usernameErr := gc.usernameFromEntityID(EntityID)
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
	loginResp, loginErr := gc.vault.Logical().Write(fmt.Sprintf("/auth/okta/login/%s", username), map[string]interface{}{
		"password": password,
	})
	if loginErr != nil {
		return "", loginErr
	}
	return loginResp.Auth.ClientToken, nil
}

func (gc *Client) isNewUser(username string) (exists bool, err error) {
	resp, err := gc.vault.Logical().Read(fmt.Sprintf("/auth/okta/users/%s", username))
	if err != nil {
		return false, err
	}
	// Determine what above looks like when no account is registered
	return resp == nil, nil
}

func (gc *Client) createEnduser(username string) (publicAddressHex string, err error) {
	createData := map[string]interface{}{
		"groups": []string{"vault-guardian-endusers"}}
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
