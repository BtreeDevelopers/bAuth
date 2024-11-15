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

export default generateToken;
