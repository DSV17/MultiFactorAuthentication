import { PrismaClient, Prisma } from "@prisma/client";
import { authenticator } from 'otplib';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { generateJWT } from "../../services/authService";
import jsonwebtoken from "jsonwebtoken";
import { createTempSessionAndToken, validateTempSession } from "../../services/tempSessionLoginService";
import { verifyMfaCode, generateMfaSecret  } from "../../services/mfaService";

import * as path from "path";
import * as fs from "fs";
import crypto from 'crypto';

const mockPrisma = {
    user: {
        findUnique: jest.fn(),
    },
    tempLoginSession: {
        create: jest.fn(),
        findUnique: jest.fn(),
        $connect: jest.fn(),
        $disconnect: jest.fn(),
        $on: jest.fn(),
        $use: jest.fn(),
        $transaction: jest.fn(),
    },
};

jest.mock('@prisma/client', () => ({
    PrismaClient: jest.fn(() => mockPrisma)
}));
jest.mock('bcryptjs');
jest.mock('jsonwebtoken');
jest.mock('crypto');
jest.mock('otplib');

const prisma = mockPrisma as unknown as jest.Mocked<PrismaClient>;;

describe('User Controller - Unit Tests', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('generateJWT', () => {
        it('should create a JWT token with the user information', async () => {
            const mockUserId = '550e8400-e29b-41d4-a716-446655440000'; 
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                hashedPassword: 'hashedPassword123',
                mfaEnabled: false
            };

            (jsonwebtoken.sign as jest.Mock).mockReturnValue('JWTToken');

            const result = generateJWT(mockUser);

            const payload = {
                sub: mockUserId,
                iat: Date.now(),
            };
            const PRIV_KEY = fs.readFileSync(
                path.join(__dirname, "..", "..", "..", "id_rsa_priv.pem"),
                "utf-8"
            );
            expect(jsonwebtoken.sign).toHaveBeenCalledWith(payload, PRIV_KEY, {
                expiresIn: "7d",
                algorithm: "RS256",
            });
            expect(result).toEqual("JWTToken");
        });
    });

    describe('createTempSessionAndToken', () => {
        const mockUserId = '550e8400-e29b-41d4-a716-446655440000';
        const mockToken = 'mocked-random-token-123456';
        const mockHashedToken = 'hashed-mocked-token-123456';
        const mockExpiresInMinutes = 5;

        beforeEach(() => {
            jest.clearAllMocks();

            // Mock fixo do Date.now para ter timestamp consistente
            jest.spyOn(Date, 'now').mockReturnValue(1633046400000);
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('should create a temporary session and return the token', async () => {
            // Setup dos mocks
            (crypto.randomBytes as jest.Mock).mockReturnValue({
                toString: () => mockToken
            });

            (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedToken);
            (prisma.tempLoginSession.create as jest.Mock).mockResolvedValue({});

            // Executar a função
            const result = await createTempSessionAndToken(prisma, mockUserId, mockExpiresInMinutes);

            // Calcular o expiresAt esperado
            const expectedExpiresAt = new Date(1633046400000 + mockExpiresInMinutes * 60 * 1000);

            // Verificações
            expect(crypto.randomBytes).toHaveBeenCalledWith(32);
            expect(crypto.randomBytes).toHaveBeenCalledTimes(1);

            expect(bcrypt.hash).toHaveBeenCalledWith(mockToken, 10);
            expect(bcrypt.hash).toHaveBeenCalledTimes(1);

            expect(prisma.tempLoginSession.create).toHaveBeenCalledWith({
                data: {
                    userId: mockUserId,
                    hashedToken: mockHashedToken,
                    expiresAt: expectedExpiresAt,
                },
            });
            expect(prisma.tempLoginSession.create).toHaveBeenCalledTimes(1);

            expect(result).toBe(mockToken);
        });

        it('should use default expiresInMinutes when not provided', async () => {
            // Setup dos mocks
            (crypto.randomBytes as jest.Mock).mockReturnValue({
                toString: () => mockToken
            });
            (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedToken);
            (prisma.tempLoginSession.create as jest.Mock).mockResolvedValue({});

            // Executar sem o segundo parâmetro
            const result = await createTempSessionAndToken(prisma, mockUserId);

            // Calcular com o valor padrão (5 minutos)
            const expectedExpiresAt = new Date(1633046400000 + 5 * 60 * 1000);

            expect(prisma.tempLoginSession.create).toHaveBeenCalledWith({
                data: {
                    userId: mockUserId,
                    hashedToken: mockHashedToken,
                    expiresAt: expectedExpiresAt,
                },
            });

            expect(result).toBe(mockToken);
        });

        it('should handle different expiration times correctly', async () => {
            const customExpiresInMinutes = 30;

            // Setup dos mocks
            (crypto.randomBytes as jest.Mock).mockReturnValue({
                toString: () => mockToken
            });
            (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedToken);
            (prisma.tempLoginSession.create as jest.Mock).mockResolvedValue({});

            // Executar com tempo customizado
            const result = await createTempSessionAndToken(prisma, mockUserId, customExpiresInMinutes);

            // Calcular com o tempo customizado
            const expectedExpiresAt = new Date(1633046400000 + customExpiresInMinutes * 60 * 1000);

            expect(prisma.tempLoginSession.create).toHaveBeenCalledWith({
                data: {
                    userId: mockUserId,
                    hashedToken: mockHashedToken,
                    expiresAt: expectedExpiresAt,
                },
            });

            expect(result).toBe(mockToken);
        });

        it('should handle bcrypt hash errors', async () => {
            const mockError = new Error('Hash failed');

            // Setup do mock para falhar
            (crypto.randomBytes as jest.Mock).mockReturnValue({
                toString: () => mockToken
            });
            (bcrypt.hash as jest.Mock).mockRejectedValue(mockError);

            // Verificar se a função rejeita com o erro
            await expect(createTempSessionAndToken(prisma, mockUserId, mockExpiresInMinutes))
                .rejects.toThrow('Hash failed');

            // Verificar que prisma.create não foi chamado em caso de erro
            expect(prisma.tempLoginSession.create).not.toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            const mockError = new Error('Database error');

            // Setup dos mocks
            (crypto.randomBytes as jest.Mock).mockReturnValue({
                toString: () => mockToken
            });
            (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedToken);
            (prisma.tempLoginSession.create as jest.Mock).mockRejectedValue(mockError);

            // Verificar se a função rejeita com o erro do banco
            await expect(createTempSessionAndToken(prisma, mockUserId, mockExpiresInMinutes))
                .rejects.toThrow('Database error');

            // Verificar que todas as funções foram chamadas, mas a última falhou
            expect(crypto.randomBytes).toHaveBeenCalled();
            expect(bcrypt.hash).toHaveBeenCalled();
            expect(prisma.tempLoginSession.create).toHaveBeenCalled();
        });
    });

    describe('validateTempSession', () => {
        const mockUserId = '550e8400-e29b-41d4-a716-446655440000';
        const mockToken = 'mocked-token-123456';
        const mockHashedToken = 'hashed-mocked-token-123456';

        beforeEach(() => {
            jest.clearAllMocks();
            // Mock fixo do Date.now para ter controle sobre o tempo
            jest.spyOn(Date, 'now').mockReturnValue(1633046400000); // 1 de Outubro de 2021
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        it('should return true for valid session with valid token and not expired', async () => {
            // Mock da sessão válida (não expirada)
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 + 10 * 60 * 1000), // 10 minutos no futuro
                createdAt: new Date(1633046400000),
            };

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).toHaveBeenCalledWith(mockToken, mockHashedToken);
            expect(result).toBe(true);
        });

        it('should return false when session is not found', async () => {
            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(null);

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).not.toHaveBeenCalled();
            expect(result).toBe(false);
        });

        it('should return false when token does not match', async () => {
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 + 10 * 60 * 1000), // 10 minutos no futuro
                createdAt: new Date(1633046400000),
            };

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockResolvedValue(false); // Token não confere

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).toHaveBeenCalledWith(mockToken, mockHashedToken);
            expect(result).toBe(false);
        });

        it('should return false when session is expired', async () => {
            // Mock da sessão expirada
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 - 10 * 60 * 1000), // 10 minutos no passado
                createdAt: new Date(1633046400000 - 20 * 60 * 1000),
            };

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true); // Token é válido, mas sessão expirada

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).toHaveBeenCalledWith(mockToken, mockHashedToken);
            expect(result).toBe(false);
        });

        it('should return false when token is valid but session is expired', async () => {
            // Cenário onde o token está correto mas a sessão já expirou
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 - 1), // 1ms no passado (expirada)
                createdAt: new Date(1633046400000 - 10 * 60 * 1000),
            };

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockResolvedValue(true);

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(result).toBe(false);
        });

        it('should return false when both token is invalid and session is expired', async () => {
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 - 10 * 60 * 1000), // 10 minutos no passado
                createdAt: new Date(1633046400000 - 20 * 60 * 1000),
            };

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockResolvedValue(false); // Token inválido

            const result = await validateTempSession(prisma, mockUserId, mockToken);

            expect(result).toBe(false);
        });

        it('should handle database errors gracefully', async () => {
            const mockError = new Error('Database connection failed');

            (prisma.tempLoginSession.findUnique as jest.Mock).mockRejectedValue(mockError);

            await expect(validateTempSession(prisma, mockUserId, mockToken))
                .rejects.toThrow('Database connection failed');

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).not.toHaveBeenCalled();
        });

        it('should handle bcrypt compare errors gracefully', async () => {
            const mockSession = {
                id: 'session-id-123',
                userId: mockUserId,
                hashedToken: mockHashedToken,
                expiresAt: new Date(1633046400000 + 10 * 60 * 1000),
                createdAt: new Date(1633046400000),
            };

            const mockError = new Error('Bcrypt compare failed');

            (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
            (bcrypt.compare as jest.Mock).mockRejectedValue(mockError);

            await expect(validateTempSession(prisma, mockUserId, mockToken))
                .rejects.toThrow('Bcrypt compare failed');

            expect(prisma.tempLoginSession.findUnique).toHaveBeenCalledWith({
                where: { userId: mockUserId }
            });
            expect(bcrypt.compare).toHaveBeenCalledWith(mockToken, mockHashedToken);
        });

        describe('edge cases', () => {
            it('should handle session expiring exactly at current time', async () => {
                // Sessão que expira exatamente agora
                const mockSession = {
                    id: 'session-id-123',
                    userId: mockUserId,
                    hashedToken: mockHashedToken,
                    expiresAt: new Date(1633046400000), // Exatamente agora
                    createdAt: new Date(1633046400000 - 5 * 60 * 1000),
                };

                (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
                (bcrypt.compare as jest.Mock).mockResolvedValue(true);

                const result = await validateTempSession(prisma, mockUserId, mockToken);

                // A sessão expirada exatamente agora deve ser considerada expirada
                expect(result).toBe(false);
            });

            it('should handle empty token', async () => {
                const mockSession = {
                    id: 'session-id-123',
                    userId: mockUserId,
                    hashedToken: mockHashedToken,
                    expiresAt: new Date(1633046400000 + 10 * 60 * 1000),
                    createdAt: new Date(1633046400000),
                };

                (prisma.tempLoginSession.findUnique as jest.Mock).mockResolvedValue(mockSession);
                (bcrypt.compare as jest.Mock).mockResolvedValue(false);

                const result = await validateTempSession(prisma, mockUserId, '');

                expect(result).toBe(false);
                expect(bcrypt.compare).toHaveBeenCalledWith('', mockHashedToken);
            });
        });
    });

    describe('verifyMfaCode', () => {
        const mockUserId = '550e8400-e29b-41d4-a716-446655440000';
        const mockCode = '123456';
        const mockMfaSecret = 'MFA_SECRET_123';

        beforeEach(() => {
            jest.clearAllMocks();
        });

        it('should return true for valid MFA code', async () => {
            // Mock do usuário com MFA configurado
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                mfaSecret: mockMfaSecret,
                mfaEnabled: true,
            };

            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (authenticator.verify as jest.Mock).mockReturnValue(true);

            const result = await verifyMfaCode(prisma, mockUserId, mockCode);

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).toHaveBeenCalledWith({
                token: mockCode,
                secret: mockMfaSecret
            });
            expect(result).toBe(true);
        });

        it('should return false for invalid MFA code', async () => {
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                mfaSecret: mockMfaSecret,
                mfaEnabled: true,
            };

            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (authenticator.verify as jest.Mock).mockReturnValue(false);

            const result = await verifyMfaCode(prisma, mockUserId, mockCode);

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).toHaveBeenCalledWith({
                token: mockCode,
                secret: mockMfaSecret
            });
            expect(result).toBe(false);
        });

        it('should throw error when user is not found', async () => {
            (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

            await expect(verifyMfaCode(prisma, mockUserId, mockCode))
                .rejects.toThrow('MFA não configurado');

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).not.toHaveBeenCalled();
        });

        it('should throw error when user does not have MFA secret', async () => {
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                mfaSecret: null, // MFA não configurado
                mfaEnabled: false,
            };

            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

            await expect(verifyMfaCode(prisma, mockUserId, mockCode))
                .rejects.toThrow('MFA não configurado');

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).not.toHaveBeenCalled();
        });

        it('should throw error when MFA secret is empty string', async () => {
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                mfaSecret: '', // MFA secret vazio
                mfaEnabled: true,
            };

            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

            await expect(verifyMfaCode(prisma, mockUserId, mockCode))
                .rejects.toThrow('MFA não configurado');

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).not.toHaveBeenCalled();
        });

        it('should handle database errors', async () => {
            const mockError = new Error('Database connection failed');

            (prisma.user.findUnique as jest.Mock).mockRejectedValue(mockError);

            await expect(verifyMfaCode(prisma, mockUserId, mockCode))
                .rejects.toThrow('Database connection failed');

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).not.toHaveBeenCalled();
        });

        it('should handle authenticator.verify errors', async () => {
            const mockUser = {
                id: mockUserId,
                email: 'test@example.com',
                mfaSecret: mockMfaSecret,
                mfaEnabled: true,
            };

            const mockError = new Error('Invalid token format');

            (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
            (authenticator.verify as jest.Mock).mockImplementation(() => {
                throw mockError;
            });

            await expect(verifyMfaCode(prisma, mockUserId, mockCode))
                .rejects.toThrow('Invalid token format');

            expect(prisma.user.findUnique).toHaveBeenCalledWith({
                where: { id: mockUserId }
            });
            expect(authenticator.verify).toHaveBeenCalledWith({
                token: mockCode,
                secret: mockMfaSecret
            });
        });

        describe('edge cases', () => {
            it('should handle empty code', async () => {
                const mockUser = {
                    id: mockUserId,
                    email: 'test@example.com',
                    mfaSecret: mockMfaSecret,
                    mfaEnabled: true,
                };

                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
                (authenticator.verify as jest.Mock).mockReturnValue(false);

                const result = await verifyMfaCode(prisma, mockUserId, '');

                expect(prisma.user.findUnique).toHaveBeenCalledWith({
                    where: { id: mockUserId }
                });
                expect(authenticator.verify).toHaveBeenCalledWith({
                    token: '',
                    secret: mockMfaSecret
                });
                expect(result).toBe(false);
            });

            it('should handle code with spaces', async () => {
                const mockUser = {
                    id: mockUserId,
                    email: 'test@example.com',
                    mfaSecret: mockMfaSecret,
                    mfaEnabled: true,
                };

                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
                (authenticator.verify as jest.Mock).mockReturnValue(false);

                const result = await verifyMfaCode(prisma, mockUserId, ' 123456 ');

                expect(authenticator.verify).toHaveBeenCalledWith({
                    token: ' 123456 ',
                    secret: mockMfaSecret
                });
                expect(result).toBe(false);
            });

            it('should handle very long code', async () => {
                const mockUser = {
                    id: mockUserId,
                    email: 'test@example.com',
                    mfaSecret: mockMfaSecret,
                    mfaEnabled: true,
                };

                const longCode = '12345678901234567890';

                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
                (authenticator.verify as jest.Mock).mockReturnValue(false);

                const result = await verifyMfaCode(prisma, mockUserId, longCode);

                expect(authenticator.verify).toHaveBeenCalledWith({
                    token: longCode,
                    secret: mockMfaSecret
                });
                expect(result).toBe(false);
            });
        });

        describe('integration with authenticator', () => {
            it('should pass correct parameters to authenticator.verify', async () => {
                const mockUser = {
                    id: mockUserId,
                    email: 'test@example.com',
                    mfaSecret: mockMfaSecret,
                    mfaEnabled: true,
                };

                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
                (authenticator.verify as jest.Mock).mockReturnValue(true);

                await verifyMfaCode(prisma, mockUserId, mockCode);

                expect(authenticator.verify).toHaveBeenCalledWith({
                    token: mockCode,
                    secret: mockMfaSecret
                });
            });

            it('should return exactly what authenticator.verify returns', async () => {
                const mockUser = {
                    id: mockUserId,
                    email: 'test@example.com',
                    mfaSecret: mockMfaSecret,
                    mfaEnabled: true,
                };

                (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);

                // Teste com true
                (authenticator.verify as jest.Mock).mockReturnValue(true);
                let result = await verifyMfaCode(prisma, mockUserId, mockCode);
                expect(result).toBe(true);

                // Teste com false
                (authenticator.verify as jest.Mock).mockReturnValue(false);
                result = await verifyMfaCode(prisma, mockUserId, mockCode);
                expect(result).toBe(false);
            });
        });
    });

    describe('generateMfaSecret', () => {
        const mockEmail = 'test@example.com';
        const mockSecret = 'MOCK_SECRET_123456';
        const mockOtpAuthUrl = 'otpauth://totp/MFA_Auth_API:test@example.com?secret=MOCK_SECRET_123456&issuer=MFA_Auth_API';

        beforeEach(() => {
            jest.clearAllMocks();
        });

        it('should generate MFA secret and OTPAuth URL for valid email', () => {
            // Setup dos mocks
            (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
            (authenticator.keyuri as jest.Mock).mockReturnValue(mockOtpAuthUrl);

            // Executar a função
            const result = generateMfaSecret(mockEmail);

            // Verificações
            expect(authenticator.generateSecret).toHaveBeenCalledTimes(1);
            expect(authenticator.generateSecret).toHaveBeenCalledWith();

            expect(authenticator.keyuri).toHaveBeenCalledTimes(1);
            expect(authenticator.keyuri).toHaveBeenCalledWith(
                mockEmail,
                'MFA_Auth_API',
                mockSecret
            );

            expect(result).toEqual({
                secret: mockSecret,
                otpauthUrl: mockOtpAuthUrl
            });
        });

        it('should handle different email formats', () => {
            const testEmails = [
                'user@example.com',
                'user.name@example.com',
                'user+tag@example.com',
                'user@sub.example.com',
                '123456@example.com'
            ];

            testEmails.forEach(email => {
                (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
                (authenticator.keyuri as jest.Mock).mockReturnValue(`otpauth://totp/MFA_Auth_API:${email}?secret=${mockSecret}&issuer=MFA_Auth_API`);

                const result = generateMfaSecret(email);

                expect(authenticator.keyuri).toHaveBeenCalledWith(
                    email,
                    'MFA_Auth_API',
                    mockSecret
                );

                expect(result.secret).toBe(mockSecret);
                expect(result.otpauthUrl).toContain(email);
            });
        });

        it('should generate different secrets for different calls', () => {
            const secrets = ['SECRET_1', 'SECRET_2', 'SECRET_3'];
            let callCount = 0;

            (authenticator.generateSecret as jest.Mock).mockImplementation(() => {
                return secrets[callCount++];
            });

            (authenticator.keyuri as jest.Mock).mockImplementation((email, issuer, secret) => {
                return `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`;
            });

            // Primeira chamada
            const result1 = generateMfaSecret('user1@example.com');
            expect(result1.secret).toBe('SECRET_1');

            // Segunda chamada
            const result2 = generateMfaSecret('user2@example.com');
            expect(result2.secret).toBe('SECRET_2');

            // Terceira chamada
            const result3 = generateMfaSecret('user3@example.com');
            expect(result3.secret).toBe('SECRET_3');

            expect(authenticator.generateSecret).toHaveBeenCalledTimes(3);
        });

        it('should include correct issuer in OTPAuth URL', () => {
            const mockSecret = 'TEST_SECRET';
            const expectedIssuer = 'MFA_Auth_API';

            (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
            (authenticator.keyuri as jest.Mock).mockImplementation((email, issuer, secret) => {
                return `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`;
            });

            const result = generateMfaSecret(mockEmail);

            expect(authenticator.keyuri).toHaveBeenCalledWith(
                mockEmail,
                expectedIssuer,
                mockSecret
            );

            // Verifica se o issuer está presente na URL
            expect(result.otpauthUrl).toContain(`issuer=${expectedIssuer}`);
        });

        it('should handle empty email', () => {
            const emptyEmail = '';
            const mockSecret = 'EMPTY_EMAIL_SECRET';
            const expectedOtpAuthUrl = 'otpauth://totp/MFA_Auth_API:?secret=EMPTY_EMAIL_SECRET&issuer=MFA_Auth_API';

            (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
            (authenticator.keyuri as jest.Mock).mockReturnValue(expectedOtpAuthUrl);

            const result = generateMfaSecret(emptyEmail);

            expect(authenticator.generateSecret).toHaveBeenCalled();
            expect(authenticator.keyuri).toHaveBeenCalledWith(
                emptyEmail,
                'MFA_Auth_API',
                mockSecret
            );

            expect(result).toEqual({
                secret: mockSecret,
                otpauthUrl: expectedOtpAuthUrl
            });
        });

        it('should handle email with special characters', () => {
            const specialEmail = 'user+test@example.com';
            const mockSecret = 'SPECIAL_SECRET';
            const expectedOtpAuthUrl = 'otpauth://totp/MFA_Auth_API:user+test@example.com?secret=SPECIAL_SECRET&issuer=MFA_Auth_API';

            (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
            (authenticator.keyuri as jest.Mock).mockReturnValue(expectedOtpAuthUrl);

            const result = generateMfaSecret(specialEmail);

            expect(authenticator.keyuri).toHaveBeenCalledWith(
                specialEmail,
                'MFA_Auth_API',
                mockSecret
            );

            expect(result.otpauthUrl).toBe(expectedOtpAuthUrl);
        });

        it('should return object with correct structure', () => {
            (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
            (authenticator.keyuri as jest.Mock).mockReturnValue(mockOtpAuthUrl);

            const result = generateMfaSecret(mockEmail);

            // Verifica a estrutura do objeto retornado
            expect(result).toHaveProperty('secret');
            expect(result).toHaveProperty('otpauthUrl');
            expect(typeof result.secret).toBe('string');
            expect(typeof result.otpauthUrl).toBe('string');

            // Verifica que as propriedades têm valores
            expect(result.secret).toBeTruthy();
            expect(result.otpauthUrl).toBeTruthy();
        });

        describe('error handling', () => {
            it('should handle authenticator.generateSecret errors', () => {
                const mockError = new Error('Failed to generate secret');

                (authenticator.generateSecret as jest.Mock).mockImplementation(() => {
                    throw mockError;
                });

                expect(() => {
                    generateMfaSecret(mockEmail);
                }).toThrow('Failed to generate secret');

                expect(authenticator.generateSecret).toHaveBeenCalled();
                expect(authenticator.keyuri).not.toHaveBeenCalled();
            });

            it('should handle authenticator.keyuri errors', () => {
                const mockError = new Error('Failed to generate OTPAuth URL');

                (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
                (authenticator.keyuri as jest.Mock).mockImplementation(() => {
                    throw mockError;
                });

                expect(() => {
                    generateMfaSecret(mockEmail);
                }).toThrow('Failed to generate OTPAuth URL');

                expect(authenticator.generateSecret).toHaveBeenCalled();
                expect(authenticator.keyuri).toHaveBeenCalled();
            });
        });

        describe('integration with authenticator', () => {
            it('should use the same secret for both operations', () => {
                let generatedSecret: string = "";

                (authenticator.generateSecret as jest.Mock).mockImplementation(() => {
                    generatedSecret = mockSecret;
                    return generatedSecret;
                });

                (authenticator.keyuri as jest.Mock).mockImplementation((email, issuer, secret) => {
                    // Verifica que o secret passado para keyuri é o mesmo gerado
                    expect(secret).toBe(generatedSecret);
                    return `otpauth://totp/${issuer}:${email}?secret=${secret}&issuer=${issuer}`;
                });

                const result = generateMfaSecret(mockEmail);

                expect(result.secret).toBe(generatedSecret);
            });

            it('should generate valid OTPAuth URL format', () => {
                (authenticator.generateSecret as jest.Mock).mockReturnValue(mockSecret);
                (authenticator.keyuri as jest.Mock).mockReturnValue(mockOtpAuthUrl);

                const result = generateMfaSecret(mockEmail);

                // Verifica padrões básicos da URL OTPAuth
                expect(result.otpauthUrl).toMatch(/^otpauth:\/\/totp\//);
                expect(result.otpauthUrl).toContain(mockEmail);
                expect(result.otpauthUrl).toContain('MFA_Auth_API');
                expect(result.otpauthUrl).toContain(mockSecret);
            });
        });
    });
});