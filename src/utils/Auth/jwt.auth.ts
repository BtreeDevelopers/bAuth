import jwt from 'jsonwebtoken';

function generateToken(params={}): string{
    return jwt.sign(
        params,
        String(process.env.JWT_SECRET),
        {
            expiresIn: '1 day'
        }
    )
}
export default generateToken;