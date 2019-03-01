# Guardian Plugin for Vault

## Usage

### Vault Server
First, turn on your development server.  This code expects that you are running it from this directory, `/plugin/vault-guardian`.  This is relevant because the `/plugin/vault-guardian/build` is where the setup script expects to put the built plugin binary:

```bash
$ [~/vault-guardian/plugin/vault-guardian] vault server -dev -dev-plugin-dir=./build
```

If you are having trouble debugging, try adding `-log-level=debug`.

### Guardian Setup
The setup script completely configures the Guardian.  It expects to be called from `/scripts`, for two reasons:
1. The relative reference from `/scripts` to `/plugins/vault-guardian/build`.
2. The policy files are all kept in `/scripts/policies`.

```bash
$ [~/vault-guardian/scripts] . setup-guardian.sh
```

If you get errors about getting HTTP responses for an HTTPS client, make sure to set:

```bash
$ export VAULT_ADDR=http://127.0.0.1:8200
```

### Enduser Flow
With that done, regular usage is dead simple.  The folder you run this from does not matter.

```bash
$ vault write guardian/login okta_username=[your username] okta_password=[your password]
```

Your response will include a client_token.  Assuming you're doing this on the CLI, you can export it to make sure that your next call uses it:

```bash
$ export VAULT_TOKEN=[the resulting token]
```

Finally, make your sign call.  The `raw_data` must be 32 bytes of hex in order for the `crypto.Sign()` function to behave -- the command below will work:

```bash
$ vault write guardian/sign raw_data=397ed6e91ab1a5f3274256aa514495d712f06db38de036ca24c5e5e5f999868d
```
