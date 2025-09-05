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

    public validateUserId(): ValidationChain{
        return body("userId").exists().withMessage("Precisa ter o campo userId")
            .isString().withMessage("Precisa ser um texto")
            .isUUID().withMessage("Precisa estar em um formato de UUID")
    }

    public validateSessioId(): ValidationChain{
        return body("sessionId").exists().withMessage("Precisa ter o campo sessionIds")
            .isString().withMessage("Precisa ser um texto")
            .isUUID().withMessage("Precisa estar em um formato de UUID")
    }

    public validateCode(): ValidationChain{
        return body("code").exists().withMessage("Precisa ter o campo code")
            .isString().withMessage("Precisa ser um texto")
            .isHexadecimal().withMessage("Precisa ser um numero hexadecimal")
            .isLength({ min: 64, max:64 }).withMessage("Precisa ter 64 caracteres/digitos")
    }

    public validateCodeMFA(): ValidationChain{
        return body("code").exists().withMessage("Precisa ter o campo code")
            .isString().withMessage("Precisa ser um texto")
            .isNumeric().withMessage("Precisa ser um numero")
            .isLength({ min: 6, max:6 }).withMessage("Precisa ter 6 digitos")
    }
}

export default new UserValidation();