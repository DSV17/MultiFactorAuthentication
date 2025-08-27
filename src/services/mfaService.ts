import { authenticator } from 'otplib';
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export const generateMfaSecret = (email: string) => {
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(email, 'MFA_Auth_API', secret);
    return { secret, otpauthUrl };
};

export const verifyMfaCode = async (userId: string, code: string) => {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.mfaSecret) throw new Error('MFA não configurado');
    return authenticator.verify({ token: code, secret: user.mfaSecret });
};