// file: example/auth_userpass.js

process.env.DEBUG = 'node-vault'; // switch on debug mode
const vault = require('./../src/index')();

//const mountPoint = 'userpass';
const username = 'quentinbeerantino@gmail.com';
const password = 'XXXXXX';

vault.oktaLogin({ username, password })
.then(console.log)
.catch((err) => console.error(err.message));


