const vault = require('../src/index')();

const org = process.env.OKTA_ORG;
const apiKey = process.env.OKTA_API_TOKEN;
const mountPoint = 'okta';
const baseUrl = process.env.OKTA_URL;

vault.auths()
.then((result) => {
  if (result.hasOwnProperty('okta/')) return undefined;
  return vault.enableAuth({
    mount_point: mountPoint,
    type: 'okta',
    description: 'OKTA auth',
  });
})
.then(() => vault.write('auth/okta/config', { org_name: org, api_token: apiKey , base_url: baseUrl}))
.then(console.log)
.catch((err) => console.error(err.message));