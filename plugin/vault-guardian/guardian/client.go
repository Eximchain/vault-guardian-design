package guardian

import (
	"github.com/hashicorp/vault/api"
	"github.com/okta/okta-sdk-golang/okta"
)

type GuardianClient struct {
	guardianToken: string
	vault: *api.Client
	okta: *okta.Client
}

func GuardianClient(oktaDomain string, oktaToken string) *GuardianClient {
	var gc GuardianClient

	// Set up Vault client with default token
	client, err = &api.NewClient()
	gc.vault = client
	gc.GuardianToken = "tokenNotSet"

	// Set up Okta client
	config := okta.NewConfig()
		.WithOrgUrl(oktaDomain)
		.WithToken(oktaToken)
	oktaClient := okta.NewClient(config, nil, nil)
	gc.okta = oktaClient
	return &gc, nil
}

func (gc *GuardianClient) pluginAuthorized() isAuthorized:bool {
	return gc.GuardianToken != "tokenNotSet"
}

func (gc *GuardianClient) authorize(secret_id string) success:bool {
	// Use secret_id to make a call to get a token
	authData := map[string]interface{}{
		"role_id" : "guardian-role-id",
		"secret_id" : secret_id
	}
	resp, err := gc.vault.Logical().Write("auth/approle/login", authData)
	if err != nil {
        return err
    }
    if resp.Auth == nil {
        return fmt.Errorf("no auth info returned")
	}
	gc.client.SetToken(resp.Auth.ClientToken)
	return true
}

func (gc *GuardianClient) oktaAccountExists(username string) exists:bool {
	// Determine what the response looks like for non-existent users
	user, resp, err := gc.okta.User.GetUser(username, nil)
	return user != nil
}

func (gc *GuardianClient) usernameFromToken(client_token string) username:string {
	resp, err := gc.vault.Logical().Write("/auth/token/lookup", map[string]interface{}{
		"token" : client_token
	})
	// TODO: How does this look in errors?  Is Write the correct method?
	return resp.Data.meta.username
}

func (gc *GuardianClient) createEnduser(username string){
	createData := map[string]interface{}{
		"username": username,
		"policies": [],
		"groups": ["guardian-enduser"]
	}
	resp, err := gc.vault.Logical().Write(fmt.Sprintf("/auth/okta/users/%s", username), createData)
	return resp
}

func (gc *GuardianClient) enduserExists(username string) username:string {
	resp, err := gc.vault.Logical().Read(fmt.Sprintf("/auth/okta/users/%s", username))
	// Determine what above looks like when no account is registered
	return resp
}

func (gc *GuardianClient) createKey(username string){
	privKeyHex, publicAddressHex := CreateKey()
	secretData := map[string]interface{}{
		"privKeyHex" : privKeyHex
		"publicAddressHex" : publicAddressHex
	}
	resp, err := gc.vault.Logical().Create(fmt.Sprintf("/secrets/%s", username))
	return resp
}

func (gc *GuardianClient) readKeyHexByUsername(username string){
	resp, err := gc.vault.Logical().Read(fmt.Sprintf("/secrets/%s", username))
	return resp.data.privKeyHex
}

func (gc *GuardianClient) readKeyHexByToken(client_token string) {
	username := gc.usernameFromToken(client_token)
	return gc.readKeyHexByUsername(username)
}

func (gc *GuardianClient) loginEnduser(username string, password string) (client_token string) {

}