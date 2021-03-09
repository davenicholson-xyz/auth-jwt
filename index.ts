import express, { Express, Request, Response, NextFunction } from "express";
import { Document, Model } from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { genSalt, hash, compare } from "bcrypt";
const router = express.Router();

interface IUser extends Document {
  email: string;
  password?: string;
}

interface DecodedJWT extends Object {
  id: string;
}

interface AuthOptions {
  maxAge?: number;
  secret?: string;
  redirect?: string;
  token?: string;
  static?: any;
  userFields?: [string] | [];
}

declare global {
  namespace Express {
    interface Request {
      auth: AuthOptions;
      user: IUser | null;
    }
  }
}

const encryptPassword = async (clearPassword: string) => {
  const salt = await genSalt();
  const epassword: string = await hash(clearPassword, salt);
  return epassword;
};

export const authjwt = (app: Express, User: Model<IUser>, options: AuthOptions = {}) => {
  app.use(cookieParser());
  app.use(express.json());

  app.use((req: Request, res: Response, next: NextFunction) => {
    req.auth = {
      secret: options.secret || "jwt_secret_key",
      redirect: options.redirect || "/",
      maxAge: options.maxAge || 3600000,
      userFields: options.userFields || [],
    };
    const token = req.cookies.access_token;
    if (token) {
      req.auth.token = token;
    }
    next();
  });

  if (options.static) {
    let root = options.static.root || "./public";
    for (let route of options.static.pages) {
      app.get(`/${route}`, requireAuth, (req: Request, res: Response, next: NextFunction) => {
        res.sendFile(`${route}.html`, { root });
      });
    }
  }

  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.auth.token) {
      jwt.verify(req.auth.token, req.auth.secret!, async (err, decoded: any) => {
        if (err) {
          req.user = null;
          app.locals.user = null;
          res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
          next();
        } else {
          try {
            req.user = await User.findById(decoded.id);
            req.user!.set("password", undefined, { strict: false });
            app.locals.user = req.user;
            next();
          } catch (err) {
            next("jwt auth error");
          }
        }
      });
    } else {
      req.user = null;
      app.locals.user = null;
      next();
    }
  });

  router.post("/register", async (req: Request, res: Response, next: NextFunction) => {
    req.body.password = req.body.password || "";
    try {
      const user = await User.create(req.body);
      user.password = await encryptPassword(req.body.password);
      await user.save();
      const token = createJWT(user._id, req.auth.secret!);
      res.cookie("access_token", token, { httpOnly: true, maxAge: req.auth.maxAge! * 1000 });
      res.json({ token });
    } catch (err) {
      next(authError(err));
    }
  });

  router.post("/signin", async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await User.findOne({ email: req.body.email });
      if (user) {
        const pmatch = await checkPassword(req.body.password, user.password!);
        if (pmatch) {
          const token = createJWT(user._id, req.auth.secret!);
          res.cookie("access_token", token, { httpOnly: true, maxAge: req.auth.maxAge! * 1000 });
          res.json({ token });
        } else {
          next("incorrect email/password");
        }
      } else {
        next("incorrect email/password");
      }
    } catch (err) {
      next(err);
    }
  });

  router.get("/signout", (req: Request, res: Response, next: NextFunction) => {
    res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
    res.redirect("/");
  });

  router.get("/user", (req: Request, res: Response, next: NextFunction) => {
    if (req.user) {
      let user: any = {};
      if (req.auth.userFields!.length > 0) {
        user["id"] = req.user._id;
        for (let field of req.auth.userFields!) {
          user[field] = req.user.get(field);
        }
      } else {
        user = req.user;
      }
      res.json({ user });
    } else {
      res.json({ user: false });
    }
  });

  app.use("/auth", router);

  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    res.json({ error: err });
  });

  return (req: Request, res: Response, next: NextFunction) => {
    next();
  };
};

export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  if (req.auth.token) {
    jwt.verify(req.auth.token, req.auth.secret!, (err, decodedToken) => {
      if (err) {
        res.redirect(req.auth.redirect!);
      } else {
        next();
      }
    });
  } else {
    console.log("Unauthorized... no JWT set");
    res.redirect(req.auth.redirect!);
  }
};

const createJWT = (userid: string, secret: string) => {
  return jwt.sign({ id: userid }, secret, { expiresIn: 360000 });
};

const checkPassword = async (clearpassword: string, password: string) => {
  const checked = await compare(clearpassword, password);
  return checked;
};

interface AuthError extends Error {
  code?: number;
  keyValue: {};
  errors?: [any];
}

const authError = (error: AuthError) => {
  if (error.code) {
    if (error.code === 11000) {
      let field = Object.keys(error.keyValue)[0];
      return `${field} has already been registered`;
    }
  }

  if (error.errors) {
    let validation = Object.values(error.errors)[0]?.properties?.message;
    return validation ?? `Somethign went wrong: ${error.toString()}`;
  }

  return error.message;
};
