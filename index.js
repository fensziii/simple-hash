const crypto        = require('crypto');
const wordlist      = require('./plugins/bundle_words.json');

const SimpleHash    = ({
    secret      = null, 
    prefix      = "DEMO", 
    nonce       = 6,  
    algorithm   = 'aes-256-ctr'
}) => {

    if(secret === null) throw Error(`set your secret`);

    const pubnonce  = nonce;
    const pubprefix = prefix;

    const key       = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32);

    var cf          = new Object();

    cf.generate     = (size, lang = "en") => {

        let trys        = 0;

        function tempgen() {

            trys = trys + 1;
            
            function ou(value, index, self) {
                return self.indexOf(value) === index;
            }

            const list      = wordlist[lang] === undefined ? wordlist["en"] : wordlist[lang];
            const shuffled  = list.sort(function(){ return .5 - Math.random() });
            const selected  = shuffled.slice(0, size);
            const unique    = selected.filter(ou);

            if(unique.length < size) return tempgen();

            return unique;  

        }

        const seed      = tempgen();
        const private   = crypto.createHash('sha256').update(JSON.stringify(seed).trim()).digest('hex').trim();

        var first_two   = private.substr(0, pubnonce);
        var last_two    = private.substr(private.length-pubnonce, private.length);
        const public    = (pubprefix + crypto.createHash('sha256').update(first_two+last_two).digest('hex')).trim();

        return { seed, private, public, public_nonce : pubnonce };
    }

    cf.verify_keys  = (private, public) => {

        var first_two   = private.trim().substr(0, pubnonce);
        var last_two    = private.trim().substr(private.trim().length-pubnonce, private.trim().length);
        const pub       = crypto.createHash('sha256').update(first_two+last_two).digest('hex');

        return pubprefix + pub === public;

    }

    cf.encrypt      = (buffer) => {

        const iv        = crypto.randomBytes(16);
        const cipher    = crypto.createCipheriv(algorithm, key, iv);
        const result    = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);

        return result;

    };

    cf.decrypt      = (encrypted) => {

       const iv         = encrypted.slice(0, 16);
       encrypted        = encrypted.slice(16);
       const decipher   = crypto.createDecipheriv(algorithm, key, iv);
       const result     = Buffer.concat([decipher.update(encrypted), decipher.final()]);

       return result;

    };

    return cf;

}

module.exports = SimpleHash;





/*

DEMO:

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

*/