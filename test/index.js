const SimpleHash    = require('./..');

const myCrypro      = SimpleHash({
    secret      : "mySecret",       // secret to use with encrypt and decrypt
    prefix      : "DEMO",           // prefix for public key
    nonce       : 6,                // select first (x) and last (x) from private key to generate public key
    algorithm   : 'aes-256-ctr'     // select hash algo to use with 
});  

// generate word seed with private-key and public-key
// input : (word amount), (language)
// return: object
var seednkeys       = myCrypro.generate(12, "en");

// verify private key and public key matches
// return: boolean
var verify          = myCrypro.verify_keys(seednkeys.private, seednkeys.public);

console.log( seednkeys, verify );


const ExampleData   = Buffer.from('Test Crypto');

// encrypt buffer
// return: buffer
const encrypted     = myCrypro.encrypt(ExampleData);
console.log('Encrypted:', encrypted);


// decrypt an encrypted buffer
// return: buffer
const decrypted     = myCrypro.decrypt(encrypted);
console.log('Decrypted:', decrypted);