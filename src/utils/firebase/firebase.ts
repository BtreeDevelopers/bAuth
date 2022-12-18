import { NextFunction, Request, Response } from 'express';

var admin = require('firebase-admin');

import serviceAccount from './firebase-key.json';

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.BUCKET,
});

const bucket = admin.storage().bucket();

const uploadImage = async (
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> => {
    if (!req.file) return next();

    const imagem = req.file;
    const nomeArquivo = req.userId + '.' + imagem.originalname.split('.').pop();

    const file = bucket.file(nomeArquivo);

    const stream = file.createWriteStream({
        metadata: {
            contentType: imagem.mimetype,
        },
    });

    stream.on('error', (e: any) => {
        console.log(e);
        return res
            .status(401)
            .json({ erro: 'Something was stoled by the roge' });
    });

    stream.on('finish', async () => {
        await file.makePublic();

        (
            req.file as any
        ).firebaseUrl = `https://storage.googleapis.com/${process.env.BUCKET}/${nomeArquivo}`;
        next();
    });

    stream.end(imagem.buffer);
};

export default uploadImage;
