import { Express, Request, Response, NextFunction } from "express";
import { Document, Model } from "mongoose";
interface IUser extends Document {
    email: string;
    password?: string;
}
interface AuthOptions {
    maxAge?: number;
    secret?: string;
    redirect?: string;
    token?: string;
    static?: any;
}
declare global {
    namespace Express {
        interface Request {
            auth: AuthOptions;
            user: IUser | null;
        }
    }
}
export declare const authjwt: (app: Express, User: Model<IUser>, options?: AuthOptions) => (req: Request, res: Response, next: NextFunction) => void;
export declare const requireAuth: (req: Request, res: Response, next: NextFunction) => void;
export {};
