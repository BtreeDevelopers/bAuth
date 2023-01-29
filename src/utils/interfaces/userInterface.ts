import { Document } from 'mongoose';

interface User extends Document {
    nome: string;
    email: string;
    senha: string;
    imagemUrl: string;
    idioma: string;
    tema: string;
    aplicativos: Array<string>;
    token_senha: string;
}

export default User;
