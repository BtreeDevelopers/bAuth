import 'dotenv/config';
import 'module-alias/register';
import App from './app';
import LoginController from './resources/controllers/login/loginController';
import UserController from './resources/controllers/user/userController';

const loginController = new LoginController();
const userController = new UserController();

userController.initialiseRoutes();
loginController.initialiseRoutes();

const app = new App(
    [userController, loginController],
    Number(process.env.PORT)
);

app.start();

app.listen();
