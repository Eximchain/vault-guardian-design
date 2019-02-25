#!/bin/bash

set -eu pipefail

PLUGIN_CONFIG_PATH="/etc/vault/config.d/plugins.hcl"
PLUGIN_PATH="../plugin/ethereum"

cd $PLUGIN_PATH


# 1. Enable Okta auth and add its configuration
vault.auths().then((res) => {
    if (res.hasOwnProperty('okta/')) return undefined;
    return vault.enableAuth({
        mount_point: OktaMount,
        type: 'okta',
        description: 'OKTA auth'
    })
}).then(()=>{
    vault.write('/auth/okta/config', {org_name, api_token, base_url})
})

# 2. Write the **Guardian**, **Enduser**, and **Maintainer** policies
vault.policies().then((res)=>{
    console.log('result of policies: ',res);
    for (var policyName of ['guardian', 'enduser', 'maintainer']) {
        await vault.addPolicy({
            name: policyName,
            rules: policyText(policyName)
        })
    }
    return;
})

# Register the Guardian plugin
## Set the plugin path
echo "plugin_directory = \"/etc/vault/vault_plugins\"" > $PLUGIN_CONFIG_PATH


# Mount the Guardian plugin at `/guardian`
vault.mounts().then(() => vault.mount({
    mount_point: GuardianMount,
    type: 'guardian',
    description: 'Guardian Plugin'
}))

# Mount a secrets engine at `/keys`
vault.mounts().then(() => vault.mount({
    mount_point: KeyMount,
    type: 'kv',
    description: 'Enduser keys'
}))

# Register a trusted Okta username (Louis or Juan), give it the **Maintainer** policy.


# Create an AppRole named `guardian`, give it the **Guardian** policy.


# Update `guardian`'s RoleId to `guardian-role-id` -- hardcoding that value means we don't need to query it.


# Get a SecretId for `guardian`, pipe it into the `/guardian/authorize` command.


# Verify the plugin is operational by calling `/guardian` with new Okta credentials.  If the plugin is able to register the user and give you a `client_token`, its authorization is working.