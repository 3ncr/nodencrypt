# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-04-26

First stable release. Published to npm as `nodencrypt@1.0.0`.

### Added

- `NodenCrypt.fromArgon2id(secret, salt)` — Argon2id KDF for password-strength
  secrets. Parameters match the [3ncr.org v1 spec](https://3ncr.org/1/#kdf):
  `m=19456 KiB, t=2, p=1`, 32-byte output, salt ≥ 16 bytes.
- Raw 32-byte key constructor — pass a `Buffer` of exactly 32 bytes to
  `new NodenCrypt(key)` to skip the KDF.
- Dual CJS + ESM build — package works from both `require` and `import`.
- GitHub Actions CI covering Node 20 / 22 / 24.

### Changed

- The `(secret, salt, iterations)` PBKDF2-SHA3 constructor is now documented as
  legacy; kept for backward compatibility with data encrypted by earlier
  versions. Prefer the raw-key or Argon2id constructor for new code.
- TypeScript upgraded to 6.x; `@types/node` updated to 25.x.
- Test runner migrated to `tsx` + node's built-in `node:test`.

## [0.9.0] - 2020-02-06

Initial public release on npm. Shipped the original PBKDF2-SHA3
`(secret, salt, iterations)` constructor and the
[3ncr.org v1 envelope](https://3ncr.org/1/) (AES-256-GCM, 12-byte random IV,
16-byte GCM tag).

[Unreleased]: https://github.com/3ncr/nodencrypt/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/3ncr/nodencrypt/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/3ncr/nodencrypt/releases/tag/v0.9.0
