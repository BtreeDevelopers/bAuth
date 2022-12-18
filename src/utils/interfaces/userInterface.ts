import { Document } from 'mongoose';

interface User extends Document {
    nome: string;
    email: string;
    senha: string;
    imagemUrl: string;
}

export default User;
