# nodencrypt (3ncr.org)

[![Lint & Test](https://github.com/3ncr/nodencrypt/actions/workflows/test.yml/badge.svg)](https://github.com/3ncr/nodencrypt/actions/workflows/test.yml)
[![npm version](https://img.shields.io/npm/v/nodencrypt.svg)](https://www.npmjs.com/package/nodencrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[3ncr.org](https://3ncr.org/) is a standard for string encryption / decryption
(algorithms + storage format), originally intended for encrypting tokens in
configuration files but usable for any UTF-8 string. v1 uses AES-256-GCM for
authenticated encryption with a 12-byte random IV:

```
3ncr.org/1#<base64(iv[12] || ciphertext || tag[16])>
```

Encrypted values look like
`3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ`.

This is the official Node.js implementation. The package ships a dual CJS + ESM
build and works from both `require` and `import`.

## Install

```bash
npm install nodencrypt
```

```js
// CommonJS
const { NodenCrypt } = require('nodencrypt');

// ES modules
import { NodenCrypt } from 'nodencrypt';
```

## Usage

Pick a constructor based on the entropy of your secret — see the
[3ncr.org v1 KDF guidance](https://3ncr.org/1/#kdf) for the canonical
recommendation.

### Recommended: raw 32-byte key (high-entropy secrets)

If you already have a 32-byte AES-256 key (random key, API token hashed to 32
bytes via SHA3-256, etc.), skip the KDF and pass it directly as a `Buffer`.

```js
const { NodenCrypt } = require('nodencrypt');
const crypto = require('crypto');

const key = crypto.randomBytes(32); // or: load from env / secret store
const nodenCrypt = new NodenCrypt(key);
```

### Recommended: Argon2id (passwords / low-entropy secrets)

For passwords or passphrases, use the async `fromArgon2id` factory. It derives
the 32-byte AES key with the parameters specified by the
[3ncr.org v1 spec](https://3ncr.org/1/#kdf): `m=19456 KiB, t=2, p=1`. The salt
must be at least 16 bytes and should be stored alongside the ciphertext (or
otherwise managed by the application).

```js
const { NodenCrypt } = require('nodencrypt');
const crypto = require('crypto');

const salt = crypto.randomBytes(16);
const nodenCrypt = await NodenCrypt.fromArgon2id('my password', salt);
```

### Legacy: PBKDF2-SHA3 (existing data only)

The original `(secret, salt, iterations)` constructor is kept for backward
compatibility with data encrypted by earlier versions. It is deprecated —
prefer the raw-key or Argon2id constructor above for new code.

```js
const nodenCrypt = new NodenCrypt(secret, salt, 1000);
```

`secret` and `salt` are inputs to PBKDF2-SHA3 (technically one is the key, the
other is the salt, but you need to store them both somewhere, preferably in
different places).

### Encrypt / decrypt

After constructing an instance, use `encrypt3ncr` and `decryptIf3ncr` (they
accept and return strings):

```js
const token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret you want to encrypt
const encryptedSecretToken = nodenCrypt.encrypt3ncr(token);
// encryptedSecretToken === '3ncr.org/1#pHRufQld0SajqjH...' (encrypted)

// ... some time later in another context ...

const decryptedSecretToken = nodenCrypt.decryptIf3ncr(encryptedSecretToken);
// decryptedSecretToken === '08019215-B205-4416-B2FB-132962F9952F'
```

`decryptIf3ncr` returns the input unchanged when it does not start with the
`3ncr.org/1#` header, so it is safe to route every configuration value through
it regardless of whether it was encrypted.

## License

MIT — see [LICENSE](LICENSE).
