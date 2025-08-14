import jsonwebtoken from "jsonwebtoken";
import bcrypt from 'bcryptjs';
import * as path from "path";
import * as fs from "fs";

const PRIV_KEY = fs.readFileSync(
    path.join(__dirname, "..", "..", "id_rsa_priv.pem"),
    "utf-8"
);

export const generateJWT = (user:any):string =>{
    const sub = user.id;
    const payload = {
      sub: sub,
      iat: Date.now(),
    };

    const jwt = jsonwebtoken.sign(payload, PRIV_KEY, {
      expiresIn: "7d",
      algorithm: "RS256",
    });

    return jwt;
}