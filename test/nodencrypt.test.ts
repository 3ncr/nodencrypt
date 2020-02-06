
import {NodenCrypt} from '../src/nodencrypt'
import * as assert from 'assert'

const t = new NodenCrypt('a', 'b', 1000);

const testVectors = new Map<string, string>(Object.entries({
    '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8': 'a',
    '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc': 'test',
    '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ':
    '08019215-B205-4416-B2FB-132962F9952F',
    '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ': 'перевірка'
}))

// test decrypt 

testVectors.forEach((value, key) => {
    assert.strictEqual(t.decryptIf3ncr(key), value)
    console.log(`[OK] decrypt(${key}) === ${value}`)
})

// test encrypt-decrypt

testVectors.forEach((value) => {
    assert.strictEqual(value, t.decryptIf3ncr(t.encrypt3ncr(value)))
    console.log(`[OK] decrypt(encrypt(${value})) === ${value} `)
})
