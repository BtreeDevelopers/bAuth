import { NextFunction, Request, Response } from 'express';

const secret = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> => {
    const secretHeader = (req.headers as any).secret;
    if (!secretHeader) {
        return res
            .status(401)
            .json({ erro: 'Something went wrong with the wizard' });
    } else {
        if (process.env.ALLOWED_APP === secretHeader) {
            return next();
        } else {
            return res.status(401).json({ erro: 'The barbarian is drunk' });
        }
    }
};

export default secret;
