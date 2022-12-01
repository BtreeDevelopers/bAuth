import userModel from "@/resources/models/userModel";
import generateToken from "@/utils/Auth/jwt.auth";
import Controller from "@/utils/interfaces/controllerInterface";
import { Router, Request, Response } from 'express';
import auth from "@/middleware/authMiddleware";

import z, {string} from 'zod'

class UserController implements Controller{
    public path = '/user';
    public router: Router;
    
    constructor(){
        this.router = Router();
    }

    public async initialiseRoutes(): Promise<void>{
        this.router.post(`${this.path}`, this.createNewUser);
        this.router.get(`${this.path}`, auth,  this.userFromToken);
    }

    private async createNewUser(req: Request, res: Response): Promise<void>{
        try {
            const newUserBody = z.object({
                nome: z.string().min(1),
                email: z.string().email(),
                senha: z.string()
            })

            const {nome, email, senha} = newUserBody.parse(req.body);

            const user = await userModel.findOne({nome, email});

            if(!user){
                const data = await userModel.create({nome,email,senha});
                const token = generateToken({id:data.id});
                res.status(201).json({token, data});
            }else{
                res.status(400).json({message: 'usuário já criado'})
            }
        } catch (error: any) {
            res.status(401).json(error);
            throw error;
        }
    }
    
    private async userFromToken(req: Request, res: Response): Promise<void> {
        try {
            const user = await userModel.findOne({ id: req.userId });
            if (!user) {
                res.status(404).json({ message: 'User could not be found' });
            } else {
                res.status(201).json(user);
            }
        } catch (error) {
            res.status(401).json(error);
            throw error;
        }
    }
}   

export default UserController;