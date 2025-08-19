import UserValidation from "../config/validator";

export function userValidator(method: string)
{
    switch(method)
    {
        case "create":
            return [UserValidation.validateEmail(), UserValidation.validatePassword()];

        case "changePassword":
            return [UserValidation.validateNewPassword()];

        case "login":
            return [UserValidation.validateEmail(), UserValidation.validatePassword()];

        default:
            return [];
    }
}