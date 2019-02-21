const vault = require('./../src/index')();

vault.initialized()
.then((result) => {
  console.log(result);
  return vault.init({ secret_shares: 1, secret_threshold: 1 });
})
.then((result) => {
  console.log(result);
  vault.token = result.root_token;
  const key = result.keys[0];
  return vault.unseal({ secret_shares: 1, key });
})
.then(console.log)
.catch((err) => console.error(err.message));

console.log("******************************************************************************************")
console.log("******************************************************************************************")
console.log("save the root key in the env file to breeze through the rest or source that and the vault enpoint")
console.log("if you are using the docker set up this in configured at VAULT_ADDR=http://127.0.0.1:8200")
