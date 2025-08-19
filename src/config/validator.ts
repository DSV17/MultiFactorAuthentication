import { body, ValidationChain } from "express-validator";

class UserValidation
{
    public validateEmail(): ValidationChain{
        return body("email").exists().withMessage("Precisa ter o campo email")
            .isString().withMessage("Precisa ser um texto")
            .isEmail().withMessage("Precisa seguir o padrão de email")
            .normalizeEmail()
    }

    public validatePassword(): ValidationChain{
        return body("password").exists().withMessage("Precisa ter o campo password")
            .isString().withMessage("Precisa ser um texto")
            .isLength({ min: 8 }).withMessage("Precisa ter pelo menos 8 caracteres")
    }

    public validateNewPassword(): ValidationChain{
        return body("newPassword").exists().withMessage("Precisa ter o campo password")
            .isString().withMessage("Precisa ser um texto")
            .isLength({ min: 8 }).withMessage("Precisa ter pelo menos 8 caracteres")
    }
}

export default new UserValidation();