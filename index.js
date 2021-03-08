"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAuth = exports.authjwt = void 0;
var express_1 = __importDefault(require("express"));
var cookie_parser_1 = __importDefault(require("cookie-parser"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var bcrypt_1 = require("bcrypt");
var router = express_1.default.Router();
var encryptPassword = function (clearPassword) { return __awaiter(void 0, void 0, void 0, function () {
    var salt, epassword;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, bcrypt_1.genSalt()];
            case 1:
                salt = _a.sent();
                return [4 /*yield*/, bcrypt_1.hash(clearPassword, salt)];
            case 2:
                epassword = _a.sent();
                return [2 /*return*/, epassword];
        }
    });
}); };
var authjwt = function (app, User, options) {
    if (options === void 0) { options = {}; }
    app.use(cookie_parser_1.default());
    app.use(express_1.default.json());
    app.use(function (req, res, next) {
        req.auth = {
            secret: options.secret || "jwt_secret_key",
            redirect: options.redirect || "/",
            maxAge: options.maxAge || 3600000,
            userFields: options.userFields || [],
        };
        var token = req.cookies.access_token;
        if (token) {
            req.auth.token = token;
        }
        next();
    });
    if (options.static) {
        var root_1 = options.static.root || "./public";
        var _loop_1 = function (route) {
            app.get("/" + route, exports.requireAuth, function (req, res, next) {
                res.sendFile(route + ".html", { root: root_1 });
            });
        };
        for (var _i = 0, _a = options.static.pages; _i < _a.length; _i++) {
            var route = _a[_i];
            _loop_1(route);
        }
    }
    app.use(function (req, res, next) {
        if (req.auth.token) {
            jsonwebtoken_1.default.verify(req.auth.token, req.auth.secret, function (err, decoded) { return __awaiter(void 0, void 0, void 0, function () {
                var _a, err_1;
                return __generator(this, function (_b) {
                    switch (_b.label) {
                        case 0:
                            if (!err) return [3 /*break*/, 1];
                            req.user = null;
                            res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
                            next();
                            return [3 /*break*/, 4];
                        case 1:
                            _b.trys.push([1, 3, , 4]);
                            _a = req;
                            return [4 /*yield*/, User.findById(decoded.id)];
                        case 2:
                            _a.user = _b.sent();
                            req.user.set("password", undefined, { strict: false });
                            next();
                            return [3 /*break*/, 4];
                        case 3:
                            err_1 = _b.sent();
                            next("jwt auth error");
                            return [3 /*break*/, 4];
                        case 4: return [2 /*return*/];
                    }
                });
            }); });
        }
        else {
            req.user = null;
            next();
        }
    });
    router.post("/register", function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var user, _a, token, err_2;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    req.body.password = req.body.password || "";
                    _b.label = 1;
                case 1:
                    _b.trys.push([1, 5, , 6]);
                    return [4 /*yield*/, User.create(req.body)];
                case 2:
                    user = _b.sent();
                    _a = user;
                    return [4 /*yield*/, encryptPassword(req.body.password)];
                case 3:
                    _a.password = _b.sent();
                    return [4 /*yield*/, user.save()];
                case 4:
                    _b.sent();
                    token = createJWT(user._id, req.auth.secret);
                    res.cookie("access_token", token, { httpOnly: true, maxAge: req.auth.maxAge * 1000 });
                    res.json({ token: token });
                    return [3 /*break*/, 6];
                case 5:
                    err_2 = _b.sent();
                    next(authError(err_2));
                    return [3 /*break*/, 6];
                case 6: return [2 /*return*/];
            }
        });
    }); });
    router.post("/signin", function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
        var user, pmatch, token, err_3;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 5, , 6]);
                    return [4 /*yield*/, User.findOne({ email: req.body.email })];
                case 1:
                    user = _a.sent();
                    if (!user) return [3 /*break*/, 3];
                    return [4 /*yield*/, checkPassword(req.body.password, user.password)];
                case 2:
                    pmatch = _a.sent();
                    if (pmatch) {
                        token = createJWT(user._id, req.auth.secret);
                        res.cookie("access_token", token, { httpOnly: true, maxAge: req.auth.maxAge * 1000 });
                        res.json({ token: token });
                    }
                    else {
                        next("incorrect email/password");
                    }
                    return [3 /*break*/, 4];
                case 3:
                    next("incorrect email/password");
                    _a.label = 4;
                case 4: return [3 /*break*/, 6];
                case 5:
                    err_3 = _a.sent();
                    next(err_3);
                    return [3 /*break*/, 6];
                case 6: return [2 /*return*/];
            }
        });
    }); });
    router.get("/signout", function (req, res, next) {
        res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
        res.redirect("/");
    });
    router.get("/user", function (req, res, next) {
        if (req.user) {
            var user = {};
            if (req.auth.userFields.length > 0) {
                user["id"] = req.user._id;
                for (var _i = 0, _a = req.auth.userFields; _i < _a.length; _i++) {
                    var field = _a[_i];
                    user[field] = req.user.get(field);
                }
            }
            else {
                user = req.user;
            }
            res.json({ user: user });
        }
        else {
            res.json({ user: false });
        }
    });
    app.use("/auth", router);
    app.use(function (err, req, res, next) {
        res.json({ error: err });
    });
    return function (req, res, next) {
        next();
    };
};
exports.authjwt = authjwt;
var requireAuth = function (req, res, next) {
    if (req.auth.token) {
        jsonwebtoken_1.default.verify(req.auth.token, req.auth.secret, function (err, decodedToken) {
            if (err) {
                res.redirect(req.auth.redirect);
            }
            else {
                next();
            }
        });
    }
    else {
        console.log("Unauthorized... no JWT set");
        res.redirect(req.auth.redirect);
    }
};
exports.requireAuth = requireAuth;
var createJWT = function (userid, secret) {
    return jsonwebtoken_1.default.sign({ id: userid }, secret, { expiresIn: 360000 });
};
var checkPassword = function (clearpassword, password) { return __awaiter(void 0, void 0, void 0, function () {
    var checked;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, bcrypt_1.compare(clearpassword, password)];
            case 1:
                checked = _a.sent();
                return [2 /*return*/, checked];
        }
    });
}); };
var authError = function (error) {
    var _a, _b;
    if (error.code) {
        if (error.code === 11000) {
            var field = Object.keys(error.keyValue)[0];
            return field + " has already been registered";
        }
    }
    if (error.errors) {
        var validation = (_b = (_a = Object.values(error.errors)[0]) === null || _a === void 0 ? void 0 : _a.properties) === null || _b === void 0 ? void 0 : _b.message;
        return validation !== null && validation !== void 0 ? validation : "Somethign went wrong: " + error.toString();
    }
    return error.message;
};
