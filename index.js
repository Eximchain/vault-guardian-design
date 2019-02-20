var options = {
  apiVersion: 'v1', // default
  endpoint: 'http://127.0.0.1:8200', // default
  token: 's.aO1udSBh500ElQXI7z0muWLA'
};

process.env.DEBUG = 'node-vault'

// get new instance of the client
var vault = require("node-vault")(options);

vault.write('secret/hello', { value: 'world', lease: '1s' }).
catch((err) => console.error(err.message));

