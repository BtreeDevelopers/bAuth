import accessModel from '@/resources/models/accessModel';
import { NextFunction, Request, Response } from 'express';

const csrf = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> => {
    const csrfHeader = (req.headers as any).csrf;
    if (!csrfHeader) {
        return res.status(401).json({ erro: 'the paladin is weak' });
    } else {
        const csrfMon = await accessModel.findOne({ csfr: csrfHeader });
        if (!csrfMon) {
            return res.status(401).json({ erro: 'The monk is wicked' });
        }
        if (csrfMon.expireAt > new Date().toISOString()) {
            if (csrfMon.csfr === csrfHeader) {
                return next();
            } else {
                return res.status(401).json({ erro: 'The barbarian is drunk' });
            }
        } else {
            return res.status(401).json({ erro: 'The dragon is strong' });
        }
    }
};

export default csrf;
