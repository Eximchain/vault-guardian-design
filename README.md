# okta-vault
Software req'd to configure and use a Vault keystore behind Okta auth.  This is an integrated, batteries-included, authentication+authorization service for one `secp256k1` private key.

> Under Construction: More details pending as docs are compiled

- Principles:
	- Keep fxnality minimal so it can slide into as many places as possible
	- Provide a clean API for consuming clients
	- Just focus on keeping keys safe and letting users sign (maybe verify?) with them

- Found Issues:
	- Vault open-source version only supports their built-in Okta Verify MFA, not Google etc.

- Open Questions:
	- A: Plugin manages a user's key and lets them sign.
	- Q: What does plugin need to connect with?
		- A: Make it an HTTPS microservice, slides into all platforms (mobile/desktop might need PopupRedirect solution)
	- Q: What do the first three user types look like?
		- A: Key variables: Funding? Technical Proficiency?  Individual or Organization?
		- A: Two end-users: person who sets up service, person who signs with it
		- A: Includes random people at hackathons who are just trying to make crypto apps.
		- A: At least also support Google, as Okta is an enterprise solution.
	- A: One instance, many users
	- A: What are the first applications that are going to use this?
		- Probably gonna be the wallet app so people don't need to directly load their private keys
	- Q: Support multiple keys?  Maybe key regeneration?
		- A: Nope, just one key.  See if the namespacing can allow for getting diff one without modifying first one

- Security Concerns:
	- Make sure to use HTTPS so attackers can't snoop the payload on its way to Vault
	- Make sure the session is one-time-use so an open session can't be re-used by an attacker

## Regular Signing User Story

0 - From within a mobile, desktop, or web application, the user clicks a button to sign a transaction.
1 - Application builds the transaction object for later.

---- plugin work begins
2 - Open a redirect popup to request Okta authentication from Vault, a la Google auth
3 - Uses Okta auth token to make a request to the `vault-signer` plugin on the Vault server
	3a - If multi-user, userId determines the signing key
4 - Signed transaction blob is returned to client
---- plugin work ends

5 - Send signed transaction to one of our tx-executors


## Initial Setup User Story

(Assumption: Company-managed key service)

1. User goes to simple page to setup their managed key
2. Login with Okta (or Google?)
3. Service checks with Vault to determine whether user already has key
	3a. If key present, allow user to export key or seed
	3b. If no key, create a key within the Vault and show the mnemonic to the user