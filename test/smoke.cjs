// Smoke test: consume the published CJS build via require().
// Mirrors the entry path real CJS users will hit.
const assert = require('assert');
const { NodenCrypt } = require('../dist/cjs/nodencrypt.js');

const t = new NodenCrypt('a', 'b', 1000);

const vectors = {
    '3ncr.org/1#I09Dwt6q05ZrH8GQ0cp+g9Jm0hD0BmCwEdylCh8': 'a',
    '3ncr.org/1#Y3/v2PY7kYQgveAn4AJ8zP+oOuysbs5btYLZ9vl8DLc': 'test',
    '3ncr.org/1#pHRufQld0SajqjHx+FmLMcORfNQi1d674ziOPpG52hqW5+0zfJD91hjXsBsvULVtB017mEghGy3Ohj+GgQY5MQ':
        '08019215-B205-4416-B2FB-132962F9952F',
    '3ncr.org/1#EPw7S5+BG6hn/9Sjf6zoYUCdwlzweeB+ahBIabUD6NogAcevXszOGHz9Jzv4vQ': 'перевірка',
};

for (const [enc, plain] of Object.entries(vectors)) {
    assert.strictEqual(t.decryptIf3ncr(enc), plain);
    assert.strictEqual(t.decryptIf3ncr(t.encrypt3ncr(plain)), plain);
}

console.log('[OK] CJS smoke test (require) passed against dist/cjs');
