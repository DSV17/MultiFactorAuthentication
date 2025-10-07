import { PrismaClient, Prisma } from "@prisma/client";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { generateJWT } from "../../services/authService";
import jsonwebtoken from "jsonwebtoken";
import { createTempSessionAndToken, validateTempSession } from "../../services/tempSessionLoginService";

import * as path from "path";
import * as fs from "fs";
import crypto from 'crypto';

const mockPrisma = {
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
});