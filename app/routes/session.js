const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const { environmentalScripts } = require("../../config/config");

function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    const prepareUserData = (user, next) => {
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);
        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) return next(err);
        });
    };

    this.isAdminUserMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return userDAO.getUserById(req.session.userId, (err, user) => {
                return user && user.isAdmin ? next() : res.redirect("/login");
            });
        }
        return res.redirect("/login");
    };

    this.isLoggedInMiddleware = (req, res, next) => {
        return req.session.userId ? next() : res.redirect("/login");
    };

    this.displayLoginPage = (req, res) => {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };

    this.handleLoginRequest = (req, res, next) => {
        const { userName, password } = req.body;
        userDAO.validateLogin(userName, password, (err, user) => {
            if (err) {
                const safeUserName = userName.replace(/(\r\n|\r|\n)/g, "_"); // 🧼 Prevent log injection
                console.log("Login error for user:", safeUserName);

                const errorMsg = err.noSuchUser ? "Invalid username" : err.invalidPassword ? "Invalid password" : "Invalid credentials";
                return res.render("login", {
                    userName,
                    password: "",
                    loginError: errorMsg,
                    environmentalScripts
                });
            }

            req.session.regenerate(() => {
                req.session.userId = user._id;
                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
            });
        });
    };

    this.displayLogoutPage = (req, res) => {
        req.session.destroy(() => res.redirect("/"));
    };

    this.displaySignupPage = (req, res) => {
        res.render("signup", {
            userName: "",
            password: "",
            passwordError: "",
            email: "",
            userNameError: "",
            emailError: "",
            verifyError: "",
            environmentalScripts
        });
    };

    const validateSignup = (userName, firstName, lastName, password, verify, email, errors) => {
        const USER_RE = /^.{1,20}$/;
        const NAME_RE = /^.{1,100}$/;
        const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;
        const PASS_RE = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,18}$/; // 🔐 Strong password

        errors.userNameError = "";
        errors.firstNameError = "";
        errors.lastNameError = "";
        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        if (!USER_RE.test(userName)) return errors.userNameError = "Invalid user name.", false;
        if (!NAME_RE.test(firstName)) return errors.firstNameError = "Invalid first name.", false;
        if (!NAME_RE.test(lastName)) return errors.lastNameError = "Invalid last name.", false;
        if (!PASS_RE.test(password)) return errors.passwordError = "Password must be 8–18 characters, with uppercase, lowercase, and number.", false;
        if (password !== verify) return errors.verifyError = "Passwords do not match.", false;
        if (email && !EMAIL_RE.test(email)) return errors.emailError = "Invalid email.", false;

        return true;
    };

    this.handleSignup = (req, res, next) => {
        const { email, userName, firstName, lastName, password, verify } = req.body;
        const errors = { userName, email };

        if (!validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            return res.render("signup", { ...errors, environmentalScripts });
        }

        userDAO.getUserByUserName(userName, (err, user) => {
            if (err) return next(err);
            if (user) {
                errors.userNameError = "User name already in use.";
                return res.render("signup", { ...errors, environmentalScripts });
            }

            userDAO.addUser(userName, firstName, lastName, password, email, (err, newUser) => {
                if (err) return next(err);
                prepareUserData(newUser, next);

                req.session.regenerate(() => {
                    req.session.userId = newUser._id;
                    newUser.userId = newUser._id;
                    return res.render("dashboard", {
                        ...newUser,
                        environmentalScripts
                    });
                });
            });
        });
    };

    this.displayWelcomePage = (req, res, next) => {
        if (!req.session.userId) return res.redirect("/login");

        userDAO.getUserById(req.session.userId, (err, doc) => {
            if (err) return next(err);
            doc.userId = req.session.userId;
            return res.render("dashboard", {
                ...doc,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;
