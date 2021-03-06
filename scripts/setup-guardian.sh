#!/bin/bash

OKTA_URL="eximchain"
OKTA_TOKEN="00YCAcHqNImh2sXiCL05-RRn-zMC0MuJIRNmBg7QjC"
PLUGIN_CONFIG_PATH="/etc/vault/config.d/plugins.hcl"
PLUGIN_CATALOG_PATH="./build"
PLUGIN_PATH="../plugin/vault-guardian/"

# Enable & configure auth plugins
vault auth enable approle
vault auth enable okta
vault write auth/okta/config \
    organization="$OKTA_URL"
    token="$OKTA_TOKEN"
    base_url="okta.com"

# Write the **Guardian**, **Enduser**, and **Maintainer** policies
vault policy write enduser ./policies/enduser.hcl
vault policy write guardian ./policies/guardian.hcl
vault policy write maintainer ./policies/maintainer.hcl

# Register the Guardian plugin
cd $PLUGIN_PATH
go build -o guardian-plugin
CHECKSUM=$(shasum -a 256 guardian-plugin | awk '{print $1}')
mv guardian-plugin $PLUGIN_CATALOG_PATH
vault write sys/plugins/catalog/secret/guardian-plugin \
    sha256=$CHECKSUM \
    command="guardian-plugin"

# Mount the Guardian plugin at /guardian
vault secrets enable -path=guardian -plugin-name=secret/guardian-plugin plugin

# Mount a secrets engine at /keys
vault secrets enable -path=keys kv

# Grant policies to appropriate Okta groups
vault write auth/okta/groups/vault-guardian-endusers policies=enduser
vault write auth/okta/groups/vault-guardian-maintainers policies=maintainer

# Create the Guardian AppRole
vault write auth/approle/role/guardian \
    secret_id_num_uses=1 \
    policies="guardian" \
    secret_id_ttl="10m" \
    secret_id_bound_cidrs="127.0.0.1/32"
    token_bound_cidrs="127.0.0.1/32"

# Update its RoleId to `guardian-role-id`
vault write auth/approle/role/guardian/role-id role_id="guardian-role-id"

# Get a SecretID, pass it into /guardian/authorize along with Okta creds
SECRET_ID=$(vault write -force auth/approle/role/guardian/secret-id | awk 'FNR == 3 {print $2}')
vault write guardian/authorize secret_id=$SECRET_ID okta_url=$OKTA_URL okta_token=$OKTA_TOKEN

cd ../../scripts