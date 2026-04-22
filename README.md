# nodencrypt (3ncr.org)

3ncr.org is a standard for string encryption/decryption (algorithms + storage format). Originally it was intended for 
encryption tokens in configuration files.  

3ncr.org v1 uses modern cryptographic primitives (SHA3-256, AES-256-GCM) and is fairly simple: 
```    
    header + base64(iv + data + tag) 
```

Encrypted data looks like this `3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8`

This is an official node.js implementation.

## Usage

### Recommended: raw 32-byte key

Pass a `Buffer` containing a 32-byte AES-256 key. Derive it however you prefer — for
passwords use Argon2id; for high-entropy inputs (random keys, API tokens) a single
SHA3-256 hash is sufficient.

```js
const { NodenCrypt } = require('nodencrypt');
const crypto = require('crypto');

const key = crypto.randomBytes(32);            // or: load from env / secret store
const nodenCrypt = new NodenCrypt(key);
```

### Password-based: Argon2id convenience factory

For low-entropy secrets (passwords, passphrases) use the async `fromArgon2id`
factory. It derives the 32-byte AES key with the parameters specified by the
[3ncr.org spec](https://3ncr.org/1/#kdf): memory 19456 KiB, iterations 2,
parallelism 1. Salt must be at least 16 bytes and should be stored alongside
the ciphertext (or otherwise managed by the application).

```js
const { NodenCrypt } = require('nodencrypt');
const crypto = require('crypto');

const salt = crypto.randomBytes(16);
const nodenCrypt = await NodenCrypt.fromArgon2id('my password', salt);
```

### Legacy: PBKDF2-SHA3 constructor

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated — prefer the
raw-key constructor above for new code.

```js
const nodenCrypt = new NodenCrypt(secret, salt, 1000);
```

`secret` and `salt` are inputs to PBKDF2-SHA3 (one of them is key, the other is salt,
but you need to store them both somewhere, preferably in different places).

You can store them in any preferred places: environment variables, files, shared
memory, derived from serial numbers or MAC. Be creative.

`1000` is the number of PBKDF2 rounds. Higher is slower and more resistant to
brute-force. If you are sure your secrets are long and random, a low value is fine.

### Encrypt / decrypt

After you created the class instance, you can use `encrypt3ncr` and `decryptIf3ncr`
(they accept and return strings):

```js
const token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret you want to encrypt 
const encryptedSecretToken = nodenCrypt.encrypt3ncr(token);
// now encryptedSecretToken === 
// '3ncr.org/1#pHRufQld0SajqjH...' (encrypted)

// ... some time later in another context ...  

const decryptedSecretToken = nodenCrypt.decryptIf3ncr(encryptedSecretToken); 
// now decryptedSecretToken === '08019215-B205-4416-B2FB-132962F9952F';
```
