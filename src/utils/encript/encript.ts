import crypto from 'crypto';

const algoritmo = 'aes256';
const segredo = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

export function criptografar(senha: string) {
    const cipher = crypto.createCipheriv(algoritmo, Buffer.from(segredo), iv);
    let retorno = cipher.update(senha, 'utf8', 'hex');
    retorno += cipher.final('hex');
    return { encryptedData: retorno.toString(), iv: iv.toString('hex') };
}

export function descriptografar(text: any) {
    let iv = Buffer.from(text.iv, 'hex');
    let encryptedText = Buffer.from(text.encryptedData, 'hex');

    // Creating the decipher from algo, key and iv
    let decipher = crypto.createDecipheriv(algoritmo, Buffer.from(segredo), iv);

    // Updating decrypted text
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    // returning response data after decryption
    return decrypted.toString();
}
