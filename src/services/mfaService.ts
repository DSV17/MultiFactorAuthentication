import { authenticator } from 'otplib';
import { PrismaClient } from "@prisma/client";
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

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

export const generateBackupCodes = (count: number = 10) => {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = crypto.randomBytes(6).toString('hex').toUpperCase();
        codes.push(code);
    }
    return codes;
};

export const hashBackupCodes = async (codes: string[]) => {
    return Promise.all(
        codes.map(async (code) => await bcrypt.hash(code, 10))
    );
};