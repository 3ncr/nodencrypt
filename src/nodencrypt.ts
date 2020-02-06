
import * as crypto from 'crypto'

const headerV1 = "3ncr.org/1#"
export class NodenCrypt {

	private readonly key: Buffer 

	constructor(secret: string, salt: string, iter: number) {
        this.key = crypto.pbkdf2Sync(secret, salt, iter, 32, 'sha3-256');
	}

	public encrypt3ncr(src: string): string {
		const iv = crypto.randomBytes(12)
		const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
		const encrypted = Buffer.concat([cipher.update(src, 'utf8'), cipher.final()]);
		const tag = cipher.getAuthTag();
		
        return headerV1 + Buffer.concat([iv, encrypted, tag]).toString('base64');
	}
	
	private decrypt(b64data: string): string|false {
		const decdata = Buffer.from(b64data, 'base64');
		if (decdata.length < 12+16) {
			return false
		}

		const iv = decdata.slice(0, 12)
		const data = decdata.slice(12, decdata.length - 16)
		const tag = decdata.slice(decdata.length - 16)

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
		decipher.setAuthTag(tag);
		
		try {
			return decipher.update(data, 'binary', 'utf8') + decipher.final('utf8')
		} catch (e) {
			return false 
		}

	}

	public decryptIf3ncr(src: string): string|false {
		if (src.startsWith(headerV1)) {
			return this.decrypt(src.substr(headerV1.length))
		}
		return src;
	}

}