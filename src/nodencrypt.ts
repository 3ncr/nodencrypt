
import * as crypto from 'crypto'
import { argon2id as wasmArgon2id } from 'hash-wasm'

const headerV1 = "3ncr.org/1#"
const aes256KeySize = 32
const nonceSizeV1 = 12
const tagSizeV1 = 16

// 3ncr.org recommended Argon2id parameters for interoperability
// (see https://3ncr.org/1/ — Key Derivation section).
const argon2idMemoryCostKiB = 19456
const argon2idTimeCost = 2
const argon2idParallelism = 1
const argon2idMinSaltBytes = 16

export class NodenCrypt {

	private readonly key: Buffer

	constructor(key: Buffer)
	/** @deprecated PBKDF2-SHA3 is the legacy KDF. Derive your own 32-byte key and pass it as a Buffer. */
	constructor(secret: string, salt: string, iter: number)
	constructor(keyOrSecret: Buffer | string, salt?: string, iter?: number) {
		if (typeof keyOrSecret === 'string') {
			if (typeof salt !== 'string' || typeof iter !== 'number') {
				throw new TypeError('NodenCrypt(secret, salt, iter): salt must be a string and iter must be a number')
			}
			this.key = crypto.pbkdf2Sync(keyOrSecret, salt, iter, aes256KeySize, 'sha3-256')
		} else {
			if (!Buffer.isBuffer(keyOrSecret)) {
				throw new TypeError('NodenCrypt(key): key must be a Buffer')
			}
			if (keyOrSecret.length !== aes256KeySize) {
				throw new RangeError(`NodenCrypt(key): key must be exactly ${aes256KeySize} bytes, got ${keyOrSecret.length}`)
			}
			this.key = keyOrSecret
		}
	}

	public encrypt3ncr(src: string): string {
		const iv = crypto.randomBytes(nonceSizeV1)
		const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
		const encrypted = Buffer.concat([cipher.update(src, 'utf8'), cipher.final()]);
		const tag = cipher.getAuthTag();

        return headerV1 + Buffer.concat([iv, encrypted, tag]).toString('base64');
	}

	private decrypt(b64data: string): string|false {
		const decdata = Buffer.from(b64data, 'base64');
		if (decdata.length < nonceSizeV1 + tagSizeV1) {
			return false
		}

		const iv = decdata.subarray(0, nonceSizeV1)
		const data = decdata.subarray(nonceSizeV1, decdata.length - tagSizeV1)
		const tag = decdata.subarray(decdata.length - tagSizeV1)

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
		decipher.setAuthTag(tag);

		try {
			return decipher.update(data).toString('utf8') + decipher.final('utf8')
		} catch (e) {
			return false
		}

	}

	public decryptIf3ncr(src: string): string|false {
		if (src.startsWith(headerV1)) {
			return this.decrypt(src.substring(headerV1.length))
		}
		return src;
	}

	/**
	 * Create a NodenCrypt using the 3ncr.org recommended Argon2id KDF for
	 * low-entropy secrets (passwords, passphrases). Parameters follow the spec
	 * (https://3ncr.org/1/ — Key Derivation): memory 19456 KiB, iterations 2,
	 * parallelism 1, output 32 bytes, salt at least 16 bytes.
	 */
	public static async fromArgon2id(secret: string | Buffer, salt: Buffer): Promise<NodenCrypt> {
		if (!Buffer.isBuffer(salt)) {
			throw new TypeError('fromArgon2id: salt must be a Buffer')
		}
		if (salt.length < argon2idMinSaltBytes) {
			throw new RangeError(`fromArgon2id: salt must be at least ${argon2idMinSaltBytes} bytes (got ${salt.length})`)
		}
		const key = await wasmArgon2id({
			password: secret,
			salt,
			iterations: argon2idTimeCost,
			parallelism: argon2idParallelism,
			memorySize: argon2idMemoryCostKiB,
			hashLength: aes256KeySize,
			outputType: 'binary',
		})
		return new NodenCrypt(Buffer.from(key))
	}

}
