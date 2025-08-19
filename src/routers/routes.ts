import { Router } from "express";
import userController from "../controllers/userController";
import { Auth } from "../middlewares/authMiddleware";
import { userValidator } from "../middlewares/userValidatorMiddleware";

const router = Router();

router.post("/user/create", userValidator("create"), userController.create);
router.get("/user/read",Auth, userController.read);
router.delete("/user/delete", Auth, userController.destroy);
router.put("/user/changePassword", Auth, userValidator("changePassword"), userController.changePassword);
router.post("/user/login", userValidator("login"), userController.login);

export default router;