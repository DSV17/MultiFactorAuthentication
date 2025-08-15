import { Router } from "express";
import userController from "../controllers/userController";
import { Auth } from "../middlewares/authMiddleware";

const router = Router();

router.post("/user/create", userController.create);
router.get("/user/read",Auth, userController.read);
router.delete("/user/delete", Auth, userController.destroy);
router.put("/user/changePassword", Auth, userController.changePassword);
router.post("/user/login", userController.login);

export default router;