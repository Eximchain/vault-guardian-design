# vault-guardian
Software req'd to configure and use a Vault keystore behind Okta auth.  This is an integrated, batteries-included, authentication+authorization service for one `secp256k1` private key.

> Principle: A minimal, clean API which keeps keys safe and lets consuming users sign with them.

## One Plugin Strategy
One angle here is to create a single plugin which handles everything: registering users, creating keys, and signing with them.  

### Endpoints
- `/guardian`
    - Unauthorized endpoint, accessible by all.
    - `create`: POST with Okta username & password; receive a single-use `client_token` for signing with a secure key tied to your account.
    - Acts as an idempotent signup method.  If we don't have a record for that Okta user, it registers them, creates their key, and then logs them in.  If they've registered before, it just logs them in.  Either way, the response is a `client_token`.
- `/guardian/sign`
    - Authorized endpoint, only accessible when authenticated under the **Enduser** policy.
    - `create`: POST with the raw data you want signed, receive a signature using your key. 
        - *Optional*: Also respond with a `fresh_client_token` which clients can provide in a subsequent sign call, giving us a compromise between security (single-use token) and convenience (don't need to re-authenticate every time).
        - *Optional*: Also include an `address_index` to instead sign with the non-zeroth address created by the key.
    - `read`: GET with no arguments, receive your public address.
- `/guardian/authorize`
    - Authorized endpoint, only accessible when authenticated under the **Maintainer** policy.
    - `create`: Call with a `SecretId` for the `guardian` AppRole, allowing the plugin to get a token for the rest of its lifetime. The `SecretId` should be single-use, it should produce tokens which can be used forever.
    - Needs to be called when the plugin process begins.  This may just be on startup using the root token, but if the plugin crashes, will be using an identity which holds the **Maintainer** policy.

### Very Rough Infrastructure Ideas
- Vault Cluster
- S3 bucket for vault backend
- Load Balancer with Vault Cluster behind it
    - Load Balancer accepts on port 443
    - (Open Question: Do we need another server between? Worried about DDOS or Security?)
- DNS name for Load Balancer
- Amazon DDOS Protection?
- Consul Cluster
- Packer builds for vault and consul
- SSH IP restrictions
- Cloudwatch Alarm on cloudwatch metrics to alert maintainers
- IAM role to Cloudwatch
    - Plugin emits metric when cannot talk to vault

### Network Protocol
A first time user's flow would look like:

![Guardian Network Protocol](protocol-diagram.jpg)

1. User POSTs to the Vault plugin at `/guardian`, an unauthenticated endpoint, including their Okta username & password in the body.
2. Plugin GETs the user from the Okta API at [`/api/v1/users/:username`](https://developer.okta.com/docs/api/resources/users#get-user-with-login), verifying they really exist in our installation.  At this point, the plugin should also check to see if that user is already registered.
3. Plugin registers user with core Vault by POSTing to [`/auth/okta/users/:username`](https://www.vaultproject.io/api/auth/okta/index.html#register-user).  They are automatically given the **Enduser** policy which gives them access to the `/guardian/sign` endpoint.
4. Plugin creates a key for the user by POSTing to core Vault at [`/keys/:username`](https://www.vaultproject.io/api/secret/kv/kv-v1.html#create-update-secret).  Stores the mnemonic, HD_PATH, and raw file, just good measure.
5. Plugin uses the earlier credentials to perform a login on behalf of the user, POSTing to core Vault at [`/auth/okta/login/:username`](https://www.vaultproject.io/api/auth/okta/index.html#login).  Core Vault handles checking those credentials against the Okta servers.
6. Plugin returns the [client token](https://www.vaultproject.io/api/auth/okta/index.html#sample-response-5) to the user so they can make a sign call.
7. User POSTs to the Vault plugin at `/guardian/sign`, an authenticated endpoint, including their data to sign in the body.
8. Plugin fetches key by GETing [`/keys/:username`](https://www.vaultproject.io/api/secret/kv/kv-v1.html#read-secret), unmarshalls it, and uses it with the provided data to produce a signature.
9. Plugin returns signature to user, key is never exposed.

### Policy Design
This strategy requires three policies:
- **Guardian**
  - Privileged policy for the plugin to use
  - `/auth/okta/users/*: ['read','create']`
  - `/auth/token/lookup: ['read']`
  - `/keys: ['read','create']`
- **Enduser**
  - Regular policy for our registered endusers
  - `/guardian/sign: ['create', 'read']`
- **Maintainer**
  - Highly privileged policy for re-authorizing Guardian
  - `/auth/approle/role/guardian/secret-id: ['create']`
  - `/guardian/authorize: ['create']`

The lack of `'update'` permissions means the privileged policy will never overwrite anybody's keys.  They do not need to create new policies -- the sign path does not require a user argument, so the same policy can be given to all future users.  The token lookup lets the plugin determine which the username corresponding to the client making the call.

### Initial Setup
When Vault initializes with the root token, we need a setup script to mount engines, create policies, and assign them to identities.  Roughly, it will:
1. Create an Okta configuration & enable the engine
2. Write the **Guardian**, **Enduser**, and **Maintainer** policies
3. Mount the Guardian plugin at `/guardian`
4. Mount a secrets engine at `/keys`
5. Register a trusted Okta username (Louis or Juan), give it the **Maintainer** policy.
    - TODO: Actually, use an Okta group so the management is more straightforward.  Create it or make sure it exists.
6. Create an AppRole named `guardian`, give it the **Guardian** policy.
7. Update `guardian`'s RoleId to `guardian-role-id` -- hardcoding that value means we don't need to query it.
8. Get a SecretId for `guardian`, pipe it into the `/guardian/authorize` command.
9. Verify the plugin is operational by calling `/guardian` with new Okta credentials.  If the plugin is able to register the user and give you a `client_token`, its authorization is working.

### Error Cases
- `/guardian`
    1. User fails to accept the push notification logging them in
    2. User provides an email that isn't in the organization
    3. Distinguish between account/key creation errors vs. login errors
- `/guardian/sign`
    1. Token has already been used
    2. Missing sign data

## Regular Signing User Story

0 - From within a mobile, desktop, or web application, the user clicks a button to sign a transaction.

1. Application builds the transaction object for later.

---- plugin work begins

2. Open a redirect popup to request Okta authentication from Vault, a la Google auth

3. Uses Okta auth token to make a request to the `vault-signer` plugin on the Vault server
  
    3a. If multi-user, userId determines the signing key

4. Signed transaction blob is returned to client

---- plugin work ends

5. Send signed transaction to one of our tx-executors


## Initial Setup User Story

(Assumption: Company-managed key service)

1. User goes to simple page to setup their managed key
2. Login with Okta (or Google?)
3. Service checks with Vault to determine whether user already has key
	3a. If key present, allow user to export key or seed
	3b. If no key, create a key within the Vault and show the mnemonic to the user

## Open Questions
- Is the whole Plugin system fast enough (without being built into the vault binary) to handle every single request related to this? One benefit to a sign-up only plugin is that only "new user signup" requests would need to hit the plugin, and then the plugin would just dump secrets and credentials that the user would use (possibly through an app on a server we control) via other built-in engines

## Answered Questions
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

## Enterprise Wishlist
This documents ideas about features or strategies that we could incorporate if we use Vault Enterprise.  Those clusters are very expensive, though, so ideally we find workarounds such that we don't need these:

- **EGP**: Endpoint Governing Policies let you create a policy on an endpoint itself, such as `/sys/policies`, rather than putting a policy onto a token.  These policies are also much more dynamic, allowing for things like checking that requests come from specific CIDR ranges. 
- **MFA**: Vault OSS supports Okta Verify Push, but no other forms of MFA.  It seems like an enterprise installation might give us a more full-featured Okta integration, such that the `login` method can include a one-time password out of something like Google Authenticator.