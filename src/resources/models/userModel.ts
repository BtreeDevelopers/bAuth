import { Schema, model } from 'mongoose';
import User from '@/utils/interfaces/userInterface';

const UserSchema = new Schema(
    {
        nome: { type: String, require: true },
        email: { type: String, require: true },
        senha: { type: String, require: true, select: false },
    },
    {
        timestamps: true,
    }
);

export default model<User>('User', UserSchema);
