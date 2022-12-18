import { NextFunction, Request, Response } from 'express';

import multer from 'multer';

const Multer = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 1024 * 1024,
    },
});

export default Multer;
