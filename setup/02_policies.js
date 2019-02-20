// file: example/policies.js

process.env.DEBUG = 'node-vault'; // switch on debug mode

const vault = require('./../src/index')();

vault.policies()
.then((result) => {
  console.log(result);
  return vault.addPolicy({
    name: 'single-user-policy',
    rules: '{ "path": { "secret/hello/*": { "capabilities": [ "read", "create" ]}}}',
  });
})

.then(() => vault.getPolicy({ name: 'single-user-policy' }))
.then(vault.policies)
.then((result) => {
  console.log(result);
  //return vault.removePolicy({ name: 'single-user-policy' });
})
.catch((err) => console.error(err.message));

setTimeout(() => {
  console.log("******************************************************************************************")
  console.log("******************************************************************************************")
  console.log("TODO: these two cant be called from the js wrapper need to run manually for now")
console.log("vault write auth/okta/groups/user-1-group policies=user-1-policy")
console.log("vault write auth/okta/users/quentinbeerantino@gmail.com groups=user-1-group")
  
}, 1000);



