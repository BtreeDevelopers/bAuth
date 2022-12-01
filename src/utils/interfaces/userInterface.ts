import { Document} from 'mongoose';

interface User extends Document{
    nome: string;
    email: string;
    senha: string;    
}

export default User;