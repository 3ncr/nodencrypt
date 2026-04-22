import { describe, test } from 'node:test'
import * as assert from 'node:assert/strict'
import * as crypto from 'crypto'
import { NodenCrypt } from '../src/nodencrypt'

const testVectors = new Map<string, string>(Object.entries({
    '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8': 'a',
    '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc': 'test',
    '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ':
        '08019215-B205-4416-B2FB-132962F9952F',
    '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ': 'перевірка',
}))

describe('legacy PBKDF2 constructor', () => {
    const t = new NodenCrypt('a', 'b', 1000)

    for (const [encrypted, plaintext] of testVectors) {
        test(`decrypts canonical vector for "${plaintext}"`, () => {
            assert.equal(t.decryptIf3ncr(encrypted), plaintext)
        })
    }

    for (const [, plaintext] of testVectors) {
        test(`encrypt/decrypt round-trip for "${plaintext}"`, () => {
            assert.equal(t.decryptIf3ncr(t.encrypt3ncr(plaintext)), plaintext)
        })
    }

    test('validates arguments', () => {
        assert.throws(() => new (NodenCrypt as any)('secret'), TypeError)
        assert.throws(() => new (NodenCrypt as any)('secret', 'salt'), TypeError)
    })
})

describe('base64 padding', () => {
    const t = new NodenCrypt('a', 'b', 1000)

    // Cover all four IV-length residues mod 3 so any padding is exercised:
    // total byte length = 12 (iv) + N (ciphertext) + 16 (tag).
    for (const plaintext of ['a', 'ab', 'abc', 'abcd', 'a longer string for padding coverage']) {
        test(`encrypted output has no '=' padding for "${plaintext}"`, () => {
            const encrypted = t.encrypt3ncr(plaintext)
            assert.ok(!encrypted.includes('='), `expected no padding, got ${encrypted}`)
        })
    }

    test('decrypts canonical (unpadded) vectors', () => {
        for (const [encrypted, plaintext] of testVectors) {
            assert.equal(t.decryptIf3ncr(encrypted), plaintext)
        }
    })

    test('decrypts the same payload with padding added', () => {
        for (const [encrypted, plaintext] of testVectors) {
            const body = encrypted.substring('3ncr.org/1#'.length)
            const padLen = (4 - (body.length % 4)) % 4
            const padded = '3ncr.org/1#' + body + '='.repeat(padLen)
            assert.equal(t.decryptIf3ncr(padded), plaintext)
        }
    })
})

describe('raw-key constructor', () => {
    const rawKey = crypto.pbkdf2Sync('a', 'b', 1000, 32, 'sha3-256')
    const tRaw = new NodenCrypt(rawKey)

    for (const [encrypted, plaintext] of testVectors) {
        test(`decrypts canonical vector for "${plaintext}"`, () => {
            assert.equal(tRaw.decryptIf3ncr(encrypted), plaintext)
        })
    }

    for (const [, plaintext] of testVectors) {
        test(`encrypt/decrypt round-trip for "${plaintext}"`, () => {
            assert.equal(tRaw.decryptIf3ncr(tRaw.encrypt3ncr(plaintext)), plaintext)
        })
    }

    test('rejects wrong-sized keys', () => {
        assert.throws(() => new NodenCrypt(Buffer.alloc(16)), /32 bytes/)
        assert.throws(() => new NodenCrypt(Buffer.alloc(33)), /32 bytes/)
    })

    test('is interoperable with legacy PBKDF2 constructor', () => {
        const t = new NodenCrypt('a', 'b', 1000)
        for (const [, plaintext] of testVectors) {
            assert.equal(tRaw.decryptIf3ncr(t.encrypt3ncr(plaintext)), plaintext)
            assert.equal(t.decryptIf3ncr(tRaw.encrypt3ncr(plaintext)), plaintext)
        }
    })
})

describe('fromArgon2id factory', () => {
    const salt = Buffer.from('0123456789abcdef', 'utf8')

    test('round-trip with the same secret and salt', async () => {
        const inst = await NodenCrypt.fromArgon2id('password', salt)
        const encrypted = inst.encrypt3ncr('hello 3ncr')
        const inst2 = await NodenCrypt.fromArgon2id('password', salt)
        assert.equal(inst2.decryptIf3ncr(encrypted), 'hello 3ncr')
    })

    test('wrong password does not decrypt', async () => {
        const inst = await NodenCrypt.fromArgon2id('password', salt)
        const encrypted = inst.encrypt3ncr('hello 3ncr')
        const inst3 = await NodenCrypt.fromArgon2id('wrong', salt)
        assert.equal(inst3.decryptIf3ncr(encrypted), false)
    })

    test('rejects salt shorter than 16 bytes', async () => {
        await assert.rejects(() => NodenCrypt.fromArgon2id('password', Buffer.alloc(15)), /at least 16 bytes/)
    })

    test('rejects non-Buffer salt', async () => {
        await assert.rejects(() => NodenCrypt.fromArgon2id('password', 'notabuffer' as any), TypeError)
    })
})
