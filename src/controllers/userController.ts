import { PrismaClient, Prisma } from "@prisma/client";
import { Response, Request } from "express";
import bcrypt from 'bcryptjs';
import { generateJWT } from "../services/authService";
import { createTempSessionAndToken, validateTempSession } from "../services/tempSessionLoginService";
import { verifyMfaCode } from "../services/mfaService";
import { generateMfaSecret } from "../services/mfaService";

const prisma = new PrismaClient();

class UserController
{
    async create(request:Request, response:Response)
    {
        try
        {
            const { email, password } = request.body;

            const user = await prisma.user.findUnique({where: { email: email }})
            if(user)
                return response.status(409).json({ message: "Usuário já existe." });

            const hashedPassword = await bcrypt.hash(password, 10);
            let userInput:Prisma.UserCreateInput = {
                email:email,
                hashedPassword:hashedPassword
            }
            const newUser = await prisma.user.create({data:userInput});

            return response.status(201).json({
                message:"Usuario criado com sucesso", 
                data:{email:newUser.email}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async read(request:Request, response:Response)
    {
        try
        {
            const id = String(request.user)
            const user = await prisma.user.findUnique({where: { id: id }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            return response.status(201).json({
                message:"Infomrações do usuário", 
                data:{id:user.id, email:user.email}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async destroy(request:Request, response:Response)
    {
        try
        {
            const id = String(request.user)
            const user = await prisma.user.findUnique({where: { id: id }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const deletedUser = await prisma.user.delete({where:{id:id}})

            return response.status(201).json({
                message:"Infomrações do usuário", 
                data:{id:deletedUser.id, email:deletedUser.email}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async changePassword(request:Request, response:Response)
    {
        try
        {
            const id = String(request.user)
            const user = await prisma.user.findUnique({where: { id: id }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const { newPassword } = request.body;

            const hashedPassword = await bcrypt.hash(newPassword, 10);
            let userInput:Prisma.UserUpdateInput = {
                hashedPassword:hashedPassword
            }
            const updatedUser = await prisma.user.update({data:userInput, where:{id:id}});

            return response.status(201).json({
                message:"Senha alterada com sucesso", 
                data:{id:updatedUser.id, email:updatedUser.email}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async login(request:Request, response:Response)
    {
        try
        {
            const { email, password } = request.body;

            const user = await prisma.user.findUnique({where: { email: email }});
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const isLogged = await bcrypt.compare(password, user.hashedPassword);
            if(!isLogged)
                return response.status(401).json({ message: "Login ou senha incorretos." });

            if(user.mfaEnabled)
            {
                const timeSession = Number(process.env.TIME_SESSION_MFA_MINUTES);
                const token = await createTempSessionAndToken(user.id, timeSession);

                return response.status(201).json({
                    message:"Codigo MFA necessario",
                    data:{mfaRequired: true, token: token, userId:user.id}
                })
            }

            const tokenJWT = generateJWT(user);

            return response.status(201).json({
                message:"Login efetuado com sucesso", 
                data:{mfaRequired: false, email:user.email, token:tokenJWT}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async verifyMfaLogin(request:Request, response:Response)
    {
        try
        {
            const { code, token, userId } = request.body;

            const user = await prisma.user.findUnique({where: { id: userId }});
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const isValidSession = await validateTempSession(userId, token);

            if(!isValidSession){
                return response.status(401).json({
                    message:"Sessão expirada ou inválida", 
                    success: false
                })
            }

            const isValidCode = await verifyMfaCode(userId, code);
            if(!isValidCode) {
                return response.status(400).json({
                    success: false,
                    message: 'Código MFA inválido',
                });
            }

            const tokenJWT = generateJWT(user);

            await prisma.tempLoginSession.delete({where:{userId:userId}});

            return response.status(201).json({
                message:"Login efetuado com sucesso", 
                data:{email:user.email, token:tokenJWT}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async setupMfa(request:Request, response:Response)
    {
        try
        {
            const userId = String(request.user)
            const user = await prisma.user.findUnique({where: { id: userId }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const {secret, otpauthUrl} = generateMfaSecret(user.email);

            await prisma.user.update({where:{id:userId}, data:{mfaSecret:secret}});

            return response.status(201).json({
                message:"MFA configurado com sucesso", 
                data:{otpauthUrl:otpauthUrl, secret:secret}
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async confirmMfa(request:Request, response:Response)
    {
        try
        {
            const userId = String(request.user)
            const user = await prisma.user.findUnique({where: { id: userId }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const {code} = request.body;

            if(!user.mfaSecret)
            {
                return response.status(400).json({
                    success: false,
                    message: 'Configure o MFA primeiro',
                });
            }

            const isValidCode = await verifyMfaCode(userId, code);
            if(!isValidCode) {
                return response.status(400).json({
                    success: false,
                    message: 'Código MFA inválido',
                });
            }

            await prisma.user.update({where:{id:user.id}, data:{mfaEnabled:true}})

            return response.status(201).json({
                message:"MFA ativado com sucesso!", 
                success: true
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }

    async disableMfa(request:Request, response:Response)
    {
        try
        {
            const userId = String(request.user)
            const user = await prisma.user.findUnique({where: { id: userId }})
            if(!user)
                return response.status(404).json({ message: "Usuário não encontrado." });

            const {password, code} = request.body;

            if(!user.mfaSecret)
            {
                return response.status(400).json({
                    success: false,
                    message: 'MFA já está desativado',
                });
            }

            const isLogged = await bcrypt.compare(password, user.hashedPassword);
            if(!isLogged)
                return response.status(401).json({ message: "Senha incorreta." });

            if(user.mfaEnabled)
            {
                const isValidCode = await verifyMfaCode(userId, code);
                if(!isValidCode) {
                    return response.status(400).json({
                        success: false,
                        message: 'Código MFA inválido',
                    });
                }
            }

            await prisma.user.update({where:{id:user.id}, data:{mfaEnabled:false}})

            return response.status(201).json({
                message:"MFA ativado com sucesso!", 
                success: true
            })
        }
        catch(error) {return response.status(500).json({ error: error })}
    }
}

export default new UserController();