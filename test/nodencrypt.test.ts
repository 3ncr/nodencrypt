
import {NodenCrypt} from '../src/nodencrypt'
import * as assert from 'assert'
import * as crypto from 'crypto'

const t = new NodenCrypt('a', 'b', 1000);

const testVectors = new Map<string, string>(Object.entries({
    '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8': 'a',
    '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc': 'test',
    '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ':
    '08019215-B205-4416-B2FB-132962F9952F',
    '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ': 'перевірка'
}))

// test decrypt with legacy PBKDF2 constructor

testVectors.forEach((value, key) => {
    assert.strictEqual(t.decryptIf3ncr(key), value)
    console.log(`[OK] decrypt(${key}) === ${value}`)
})

// test encrypt-decrypt with legacy PBKDF2 constructor

testVectors.forEach((value) => {
    assert.strictEqual(value, t.decryptIf3ncr(t.encrypt3ncr(value)))
    console.log(`[OK] decrypt(encrypt(${value})) === ${value} `)
})

// test raw-key constructor: same underlying key as ('a', 'b', 1000) must decrypt the same vectors

const rawKey = crypto.pbkdf2Sync('a', 'b', 1000, 32, 'sha3-256')
const tRaw = new NodenCrypt(rawKey)

testVectors.forEach((value, key) => {
    assert.strictEqual(tRaw.decryptIf3ncr(key), value)
    console.log(`[OK] raw-key decrypt(${key}) === ${value}`)
})

testVectors.forEach((value) => {
    assert.strictEqual(value, tRaw.decryptIf3ncr(tRaw.encrypt3ncr(value)))
    console.log(`[OK] raw-key decrypt(encrypt(${value})) === ${value} `)
})

// cross-compatibility: raw-key instance decrypts what legacy instance encrypts, and vice versa
testVectors.forEach((value) => {
    assert.strictEqual(value, tRaw.decryptIf3ncr(t.encrypt3ncr(value)))
    assert.strictEqual(value, t.decryptIf3ncr(tRaw.encrypt3ncr(value)))
})
console.log('[OK] raw-key and legacy PBKDF2 constructors are interoperable')

// test raw-key constructor rejects wrong-sized keys
assert.throws(() => new NodenCrypt(Buffer.alloc(16)), /32 bytes/)
assert.throws(() => new NodenCrypt(Buffer.alloc(33)), /32 bytes/)
console.log('[OK] raw-key constructor rejects wrong key sizes')

// test legacy constructor still validates its arguments
assert.throws(() => new (NodenCrypt as any)('secret'), TypeError)
assert.throws(() => new (NodenCrypt as any)('secret', 'salt'), TypeError)
console.log('[OK] legacy constructor validates arguments')

// test Argon2id factory

async function testArgon2id() {
    const salt = Buffer.from('0123456789abcdef', 'utf8')

    // round-trip: encrypt with one instance, decrypt with a second instance created
    // from the same secret + salt. Proves the KDF is deterministic for fixed params.
    const inst = await NodenCrypt.fromArgon2id('password', salt)
    const encrypted = inst.encrypt3ncr('hello 3ncr')
    const inst2 = await NodenCrypt.fromArgon2id('password', salt)
    assert.strictEqual(inst2.decryptIf3ncr(encrypted), 'hello 3ncr')
    console.log('[OK] fromArgon2id round-trip')

    // a different password must NOT decrypt (authenticated GCM returns false on bad key)
    const inst3 = await NodenCrypt.fromArgon2id('wrong', salt)
    assert.strictEqual(inst3.decryptIf3ncr(encrypted), false)
    console.log('[OK] fromArgon2id wrong password does not decrypt')

    // salt shorter than 16 bytes must throw
    const shortSalt = Buffer.alloc(15)
    await assert.rejects(() => NodenCrypt.fromArgon2id('password', shortSalt), /at least 16 bytes/)
    console.log('[OK] fromArgon2id rejects salt shorter than 16 bytes')

    // non-Buffer salt must throw
    await assert.rejects(() => NodenCrypt.fromArgon2id('password', 'notabuffer' as any), TypeError)
    console.log('[OK] fromArgon2id rejects non-Buffer salt')
}

testArgon2id().catch((err) => {
    console.error(err)
    process.exit(1)
})
