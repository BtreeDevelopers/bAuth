import { Schema, model } from 'mongoose';
import User from '@/utils/interfaces/userInterface';

const UserSchema = new Schema(
    {
        nome: { type: String, require: true },
        email: { type: String, require: true },
        senha: { type: String, require: true, select: false },
        imagemUrl: { type: String, require: true },
        idioma: { type: String, require: true },
        tema: { type: String, require: true },
        aplicativos: { type: [String], require: true },
    },
    {
        timestamps: true,
    }
);

export default model<User>('User', UserSchema);
