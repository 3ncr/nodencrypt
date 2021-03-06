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


```js
const nodenCrypt = new NodenCrypt(secret, salt, 1000);
```

`secret` and `salt` - are encryption keys (technically one of them is key, another is salt, but you need to store them both somewhere, 
preferably in different places). 

You can store them any preferred places: environment variables, files, shared memory, 
drive from serial numbers or MAC. Be creative. 

`1000` - is a number of PBKDF2 rounds. 
The more is better and slower. 
If you are sure that your secrets are long and random, you can keep this value reasonable low.  

After you created the class instance, you can just use encrypt3ncr and decrypt3ncr methods (they accept and return strings):

```js
const token = '08019215-B205-4416-B2FB-132962F9952F'; // your secret you want to encrypt 
const encryptedSecretToken = nodenCrypt.encrypt3ncr(token);
// now encryptedSecretToken === 
// '3ncr.org/1#pHRufQld0SajqjH...' (encrypted)

// ... some time later in another context ...  

const decryptedSecretToken = nodenCrypt.decryptIf3ncr(encryptedSecretToken); 
// now decryptedSecretToken === ''08019215-B205-4416-B2FB-132962F9952F';
```


