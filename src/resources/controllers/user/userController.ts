import userModel from '@/resources/models/userModel';
import generateToken from '@/utils/Auth/jwt.auth';
import Controller from '@/utils/interfaces/controllerInterface';
import { Router, Request, Response } from 'express';
import auth from '@/middleware/authMiddleware';

import z, { string } from 'zod';
import secret from '@/middleware/secretMiddleware';
import Multer from '@/middleware/multerMiddleware';
import uploadImage from '@/utils/firebase/firebase';
import mongoose from 'mongoose';

import bcryptjs from 'bcryptjs';
import csrf from '@/middleware/csfrMiddleware';
import accessModel from '@/resources/models/accessModel';
import { descriptografar } from '@/utils/encript/encript';
import axios from 'axios';
import { compare } from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

class UserController implements Controller {
    public path = '/user';
    public router: Router;

    constructor() {
        this.router = Router();
    }

    public async initialiseRoutes(): Promise<void> {
        this.router.post(`${this.path}`, csrf, this.createNewUser);
        this.router.get(`${this.path}`, auth, this.userFromToken);
        this.router.get(`${this.path}/users`, [auth, secret], this.getAllUser);
        this.router.get(
            `${this.path}/users/:typeparam/:param`,
            [auth, secret],
            this.getUserByParam
        );
        this.router.post(`${this.path}/list`, secret, this.getFromList);
        this.router.post(
            `${this.path}/image`,
            auth,
            Multer.single('imagem'),
            uploadImage,
            this.uploadImage
        );
        this.router.put(`${this.path}/editaccount`, auth, this.editarConta);

        this.router.post(`${this.path}/delete`, auth, this.deleteaccount);

        this.router.post(`${this.path}/apps`, auth, this.editarapps);

        this.router.post(`${this.path}/recover`, this.askToRecover);

        this.router.post(`${this.path}/recover/:token`, this.recover);
    }

    private async createNewUser(req: Request, res: Response): Promise<any> {
        try {
            const csrfHeader = (req.headers as any).csrf;
            const csrfMon = await accessModel.findOneAndDelete({
                csfr: csrfHeader,
            });

            const newUserBody = z.object({
                nome: z.string().min(1),
                email: z.string().email(),
                senha: z.string(),
                idioma: z.string().optional(),
                tema: z.string().optional(),
            });

            const { nome, email, senha, idioma, tema } = newUserBody.parse(
                req.body
            );
            let aplicativo = descriptografar({
                encryptedData: csrfMon?.app,
                iv: csrfMon?.iv,
            });

            const user = await userModel.findOne({ email });

            if (!user) {
                const hash = await bcryptjs.hash(senha, 10);
                const data = await userModel.create({
                    nome,
                    email,
                    senha: hash,
                    idioma: idioma || 'br',
                    tema: tema || 'dark',
                    aplicativos: aplicativo !== 'bauth' ? [aplicativo] : [],
                });

                const conBMAIL = axios.create({
                    baseURL: String(process.env.BMAIL_URL),
                    headers: {
                        'Accept-Encoding': '*',
                    },
                });
                await conBMAIL.post('/send_email/welcome_email', {
                    userName: nome,
                    userEmail: email,
                });

                return res.status(201).json({
                    data: { nome: data.nome, email: data.email, _id: data._id },
                });
            } else {
                return res.status(400).json({ message: 'usuário já criado' });
            }
        } catch (error: any) {
            return res.status(401).json(error);
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
            console.log(req.body);
            const listArray = listBody.parse(req.body);
            const user = await userModel.find({
                _id: { $in: listArray.listArray },
            });
            console.log(user);
            return res.status(201).json({ user });
        } catch (error) {
            //console.log(error);
            return res.status(500).json({ message: 'Something went wrong' });
        }
    }

    private async uploadImage(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const firebaseUrl = (req.file as any)?.firebaseUrl || '';

            await userModel.updateOne(
                { _id: req.userId },
                { imagemUrl: firebaseUrl }
            );
            await session.commitTransaction();
            return res.status(200).json({
                message: 'User Image Updated',
                imagemUrl: firebaseUrl,
            });
        } catch (error) {
            console.log(error);
            await session.abortTransaction();
            return res.status(401).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
    private async editarConta(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const editUserBody = z.object({
                userId: z.string(),
                nome: z.string().min(1).optional(),
                email: z.string().email().optional(),
                idioma: z.string().optional(),
                tema: z.string().optional(),
            });
            const { userId, nome, email, idioma, tema } = editUserBody.parse(
                req.body
            );

            const user = await userModel.findById(userId);
            if (!user) {
                throw new Error('User data not found');
            }
            await userModel.updateOne(
                { _id: userId },
                {
                    nome: nome || user.nome,
                    email: email || user.email,
                    idioma: idioma || user.idioma,
                    tema: tema || user.tema,
                }
            );

            await session.commitTransaction();
            return res.status(201).json({ message: 'Update with success' });
        } catch (error: any) {
            console.log(error);
            await session.abortTransaction();
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
    private async deleteaccount(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const deleteUserBody = z.object({
                userId: z.string(),
                senha: z.string(),
            });
            const { userId, senha } = deleteUserBody.parse(req.body);

            const user = await userModel.findById(userId).populate('senha');
            if (!user) throw new Error('Usuário ou senha incorretos');

            const passwordMatch = await compare(senha, user.senha);
            if (!passwordMatch) throw new Error('Senha não confere');

            const conBJRD = axios.create({
                baseURL: String(process.env.BJORD_URL),
                headers: {
                    'Accept-Encoding': '*',
                },
            });
            const conPC = axios.create({
                baseURL: String(process.env.PC_URL),
                headers: {
                    'Accept-Encoding': '*',
                },
            });

            await conBJRD.delete('/login/' + userId);
            await conPC.delete('/delete/' + userId);

            await userModel.findOneAndDelete({ _id: userId });
            await session.commitTransaction();
            return res.status(200).json({ message: 'Delete with success' });
        } catch (error) {
            console.log(error);
            await session.abortTransaction();
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
    private async editarapps(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();
        try {
            const appsBody = z.object({
                userId: z.string(),
                aplicativos: z.array(z.string()),
            });
            const { userId, aplicativos } = appsBody.parse(req.body);

            const user = await userModel.findById(userId);

            if (!user) {
                throw new Error('user not found');
            }
            await userModel.findByIdAndUpdate(userId, {
                $set: {
                    aplicativos: aplicativos,
                },
            });

            await session.commitTransaction();
        } catch (error: any) {
            await session.abortTransaction();
            if (error.message === 'user not found') {
                return res.status(401).json({ message: 'user not found' });
            }
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
    private async askToRecover(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const Body = z.object({
                email: z.string().email(),
            });
            const { email } = Body.parse(req.body);
            const user = await userModel.findOne({
                email: email,
            });

            if (!user) {
                throw new Error('user not found');
            }
            const keyToAccess = uuidv4();

            await userModel.updateOne(
                { _id: user.id },
                {
                    token_senha: keyToAccess,
                }
            );

            const conBMAIL = axios.create({
                baseURL: String(process.env.BMAIL_URL),
                headers: {
                    'Accept-Encoding': '*',
                },
            });
            await conBMAIL.post('/send_email/change_password_email', {
                userName: user.nome,
                userEmail: user.email,
                changePasswordLink:
                    'https://btreeauth.web.app/password/' + keyToAccess,
            });
            await session.commitTransaction();
            return res.status(200).json({ message: 'email sent' });
        } catch (error: any) {
            await session.abortTransaction();
            if (error.message === 'user not found') {
                return res.status(401).json({ message: 'user not found' });
            }
            console.log(error);
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
    private async recover(req: Request, res: Response): Promise<any> {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const token = req.params.token;
            if (!token || token === '') {
                throw new Error('param not found');
            }
            const user = await userModel.findOne({ token_senha: token });

            if (!user) {
                throw new Error('token is not valid');
            }

            const alterSenha = z.object({
                senha: z.string(),
            });

            const { senha } = alterSenha.parse(req.body);

            const hash = await bcryptjs.hash(senha, 10);

            await userModel.findByIdAndUpdate(user.id, {
                token_senha: '',
                senha: hash,
            });
            await session.commitTransaction();
            return res.status(200).json({ message: 'alterado' });
        } catch (error: any) {
            await session.abortTransaction();
            if (error.message === 'param not found') {
                return res.status(401).json({ message: 'param not found' });
            }
            if (error.message === 'token is not valid') {
                return res.status(401).json({ message: 'token is not valid' });
            }
            return res.status(500).json({ message: 'Something went wrong' });
        } finally {
            await session.endSession();
        }
    }
}

export default UserController;
