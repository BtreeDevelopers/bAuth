import { Document } from 'mongoose';

interface Access extends Document {
    csfr: string;
    expireAt: string;
    app: string;
    iv: string;
}

export default Access;
