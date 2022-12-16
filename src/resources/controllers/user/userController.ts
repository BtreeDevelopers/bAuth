import userModel from '@/resources/models/userModel';
import generateToken from '@/utils/Auth/jwt.auth';
import Controller from '@/utils/interfaces/controllerInterface';
import { Router, Request, Response } from 'express';
import auth from '@/middleware/authMiddleware';

import z, { string } from 'zod';
import secret from '@/middleware/secretMiddleware';

class UserController implements Controller {
    public path = '/user';
    public router: Router;

    constructor() {
        this.router = Router();
    }

    public async initialiseRoutes(): Promise<void> {
        this.router.post(`${this.path}`, this.createNewUser);
        this.router.get(`${this.path}`, auth, this.userFromToken);
        this.router.get(`${this.path}/users`, [auth, secret], this.getAllUser);
        this.router.get(
            `${this.path}/users/:typeparam/:param`,
            [auth, secret],
            this.getUserByParam
        );
        this.router.post(`${this.path}/list`, secret, this.getFromList);
    }

    private async createNewUser(req: Request, res: Response): Promise<void> {
        try {
            const newUserBody = z.object({
                nome: z.string().min(1),
                email: z.string().email(),
                senha: z.string(),
            });

            const { nome, email, senha } = newUserBody.parse(req.body);

            const user = await userModel.findOne({ nome, email });

            if (!user) {
                const data = await userModel.create({ nome, email, senha });
                const token = generateToken({ id: data.id });
                res.status(201).json({ token, data });
            } else {
                res.status(400).json({ message: 'usuário já criado' });
            }
        } catch (error: any) {
            res.status(401).json(error);
            throw error;
        }
    }

    private async userFromToken(req: Request, res: Response): Promise<void> {
        try {
            const user = await userModel.findOne({ _id: req.userId });
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

    private async getAllUser(req: Request, res: Response): Promise<any> {
        try {
            const user = await userModel.find({});
            return res.status(201).json({ user });
        } catch (error) {
            return res.status(500).json({ message: 'Something went wrong' });
        }
    }

    private async getUserByParam(req: Request, res: Response): Promise<any> {
        try {
            if (
                !req.params.param ||
                req.params.param === '' ||
                !req.params.typeparam ||
                req.params.typeparam === ''
            ) {
                return res.status(500).json({ message: 'Missing Params' });
            }

            if (req.params.typeparam === 'id') {
                const user = await userModel.findById(req.params.param);
                return res.status(201).json({ user });
            }

            if (req.params.typeparam === 'email') {
                const user = await userModel.find({
                    email: req.params.param,
                });
                return res.status(201).json({ user });
            }

            if (req.params.typeparam === 'nome') {
                const user = await userModel.find({
                    nome: req.params.param,
                });
                return res.status(201).json({ user });
            }
        } catch (error) {
            return res.status(500).json({ message: 'Something went wrong' });
        }
    }

    private async getFromList(req: Request, res: Response): Promise<any> {
        try {
            const listBody = z.object({
                listArray: z.array(z.string()),
            });

            const listArray = listBody.parse(req.body);
            const user = await userModel.find({
                _id: { $in: listArray.listArray },
            });

            return res.status(201).json({ user });
        } catch (error) {
            return res.status(500).json({ message: 'Something went wrong' });
        }
    }
}

export default UserController;
