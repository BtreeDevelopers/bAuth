import Controller from '@/utils/interfaces/controllerInterface';
import userModel from '@/resources/models/userModel';
import accessModel from '@/resources/models/accessModel';
import generateToken from '@/utils/Auth/jwt.auth';

import { Router, Request, Response } from 'express';
import z, { string } from 'zod';
import { compare } from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import mongoose from 'mongoose';

import csrf from '@/middleware/csfrMiddleware';
import { criptografar, descriptografar } from '@/utils/encript/encript';

class LoginController implements Controller {
    public path = '/login';
    public router: Router;

    constructor() {
        this.router = Router();
    }

    public async initialiseRoutes(): Promise<void> {
        this.router.post(`${this.path}`, csrf, this.login);
        this.router.get(`${this.path}/csrf`, this.criarCSFR);
    }

    private async login(req: Request, res: Response): Promise<any> {
        try {
            const csrfHeader = (req.headers as any).csrf;

            const loginUser = z.object({
                email: string().email(),
                senha: string(),
            });

            const { email, senha } = loginUser.parse(req.body);

            const user = await userModel
                .findOne({ email: email })
                .populate('senha');

            if (!user) {
                return res
                    .status(401)
                    .json({ message: 'Usuário não cadastrado' });
            } else {
                const passwordMatch = await compare(senha, user.senha);
                if (!passwordMatch)
                    throw new Error('Usuário ou senha incorretos');
                const csrfMon = await accessModel.findOneAndDelete({
                    csfr: csrfHeader,
                });
                const token = generateToken({ id: user._id });
                return res.status(200).json({
                    token,
                    user: {
                        _id: user._id,
                        nome: user.nome,
                        email: user.email,
                        imagemUrl: user.imagemUrl,
                        idioma: user.idioma,
                        tema: user.tema,
                    },
                    url_retorno: descriptografar({
                        encryptedData: csrfMon?.app,
                        iv: csrfMon?.iv,
                    }),
                });
            }
        } catch (error: any) {
            if (error.message === 'Usuário ou senha incorretos') {
                return res
                    .status(401)
                    .json({ message: 'Usuário ou senha incorretos' });
            }
            console.log(error);
            return res.status(400).json({ error });
        }
    }
    private async criarCSFR(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const origem = req.get('origin');
            console.log(origem);
            const validURL = (req.headers as any).url_retorno;
            if (!validURL) {
                return res
                    .status(401)
                    .json({ erro: 'A valid url was not found' });
            }

            const keyToAccess = uuidv4();

            let expireAt = new Date();
            expireAt.setHours(expireAt.getHours() + 1);
            let criptogra = criptografar(validURL);

            accessModel.create({
                csfr: keyToAccess,
                expireAt: expireAt.toISOString(),
                app: criptogra.encryptedData,
                iv: criptogra.iv,
            });
            await session.commitTransaction();
            return res.status(200).json({ csfr: keyToAccess, origem });
        } catch (error: any) {
            console.log(error);
            await session.abortTransaction();
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
}

export default LoginController;
