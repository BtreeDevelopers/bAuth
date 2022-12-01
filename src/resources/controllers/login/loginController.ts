import Controller from "@/utils/interfaces/controllerInterface";
import userModel from "@/resources/models/userModel";
import generateToken from "@/utils/Auth/jwt.auth";
import { Router, Request, Response } from 'express';
import z, {string} from 'zod'

class LoginController implements Controller{
    public path = '/login';
    public router: Router;
    
    constructor(){
        this.router = Router();
    }

    public async initialiseRoutes(): Promise<void>{
        this.router.post(`${this.path}`, this.login);
        
    }

    private async login (req: Request,res: Response): Promise<void>{
        try {
            const loginUser = z.object({
                email: string().email(),
                senha: string(),
            });

            const { email , senha } = loginUser.parse(req.body);

            const user = await userModel.findOne({email,senha});

            if(!user){
                res.status(401).json({message: 'Usuário não cadastrado'})
            }else{
                const token = generateToken({id:user.id});
                res.status(200).json({token,user});
            }
        } catch (error) {
            res.status(400).json({error})
            throw error;
        }
    }
    
}

export default LoginController;