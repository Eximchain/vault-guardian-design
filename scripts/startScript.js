process.env.DEBUG = 'node-vault'; // switch on debug mode
import policyText from '../policies/getPolicy';

const vault = require('./../src/index')();

const org_name = process.env.OKTA_ORG;
const api_token = process.env.OKTA_API_TOKEN;
const base_url = process.env.OKTA_URL;

const OktaMount = 'okta';
const KeyMount = 'keys';
const GuardianMount = 'guardian';

const setup = async () => {
    // 1. Enable Okta auth and add its configuration
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

    // 2. Write the **Guardian**, **Enduser**, and **Maintainer** policies
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

    // Register the Guardian plugin -- not supported by node-vault,
    // just writing out the commands.
    

    // Mount the Guardian plugin at `/guardian`
    vault.mounts().then(() => vault.mount({
        mount_point: GuardianMount,
        type: 'guardian',
        description: 'Guardian Plugin'
    }))

    // Mount a secrets engine at `/keys`
    vault.mounts().then(() => vault.mount({
        mount_point: KeyMount,
        type: 'kv',
        description: 'Enduser keys'
    }))

    // Register a trusted Okta username (Louis or Juan), give it the **Maintainer** policy.


    // Create an AppRole named `guardian`, give it the **Guardian** policy.


    // Update `guardian`'s RoleId to `guardian-role-id` -- hardcoding that value means we don't need to query it.


    // Get a SecretId for `guardian`, pipe it into the `/guardian/authorize` command.


    // Verify the plugin is operational by calling `/guardian` with new Okta credentials.  If the plugin is able to register the user and give you a `client_token`, its authorization is working.

}

setup();