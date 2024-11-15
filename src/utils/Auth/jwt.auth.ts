import jwt from 'jsonwebtoken';

function generateToken(params = {}): string {
    return jwt.sign(params, String(process.env.JWT_SECRET), {
        expiresIn: '1 day',
    });
}

export function openToken(token: string) {
    const dados = jwt.verify(token, String(process.env.JWT_SECRET));

    return dados as any;
}

export function parseJwt(token: string) {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
}

export default generateToken;
