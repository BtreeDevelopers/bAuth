import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const auth = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ erro: 'Token not found' });
    } else {
        const parts = authHeader.split(' ');
        if (!(parts.length === 2)) {
            return res.status(401).json({ erro: 'Token not found' });
        } else {
            const [scheme, token] = parts;

            if (!/^Bearer$/i.test(scheme)) {
                return res.status(401).json({ erro: 'Token seems broken' });
            }
            jwt.verify(
                token,
                String(process.env.JWT_SECRET),
                (err, decoded: any) => {
                    if (err) {
                        return res.status(401).json({ erro: 'Token unvalid' });
                    }
                    req.userId = decoded.id;
                    return next();
                }
            );
        }
    }
};

export default auth;
