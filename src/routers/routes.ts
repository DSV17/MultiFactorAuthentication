import { Router } from "express";
import userController from "../controllers/userController";
import { Auth } from "../middlewares/authMiddleware";
import { userValidator } from "../middlewares/userValidatorMiddleware";

const router = Router();

//Rotas padrão de usuário
router.post("/user/create", userValidator("create"), userController.create);
router.get("/user/read", Auth, userController.read);
router.delete("/user/delete", Auth, userController.destroy);
router.put("/user/changePassword", Auth, userValidator("changePassword"), userController.changePassword);

//Rotas de login
router.post("/user/login", userValidator("login"), userController.login);
router.post("/user/MfaLogin", userValidator("MfaLogin"), userController.verifyMfaLogin);

//Rotas de gerenciamento de sistema MFA
router.get("/user/setupMfa", Auth, userValidator("setupMfa"), userController.setupMfa);
router.post("/user/confirmMfa", Auth, userValidator("confirmMfa"), userController.confirmMfa);
router.post("/user/disableMfa", Auth, userValidator("disableMfa"), userController.disableMfa);

export default router;