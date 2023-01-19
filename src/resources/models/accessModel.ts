import Access from '@/utils/interfaces/accessInterface';
import { Schema, model } from 'mongoose';

const AccessSchema = new Schema(
    {
        csfr: { type: String, require: true },
        expireAt: { type: String, require: true },
        app: { type: String, require: true },
        iv: { type: String, require: true },
    },
    { timestamps: true }
);

export default model<Access>('Access', AccessSchema);
