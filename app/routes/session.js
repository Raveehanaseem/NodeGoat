const validator = require('validator');
const jwt = require('jsonwebtoken');
const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");

/* The SessionHandler must be constructed with a connected db */
function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);

    const prepareUserData = (user, next) => {
        // Generate random allocations
        const stocks = Math.floor((Math.random() * 40) + 1);
        const funds = Math.floor((Math.random() * 40) + 1);
        const bonds = 100 - (stocks + funds);

        allocationsDAO.update(user._id, stocks, funds, bonds, (err) => {
            if (err) return next(err);
        });
    };

   // Middleware to check admin status
   this.isAdminUserMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || !decoded.isAdmin) return res.redirect("/login");
        next();
    });
};

// Middleware to check login status
this.isLoggedInMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.redirect("/login");
        req.userId = decoded.id;
        next();
    });
};

    this.displayLoginPage = (req, res, next) => {
        return res.render("login", {
            userName: "",
            password: "",
            loginError: "",
            environmentalScripts
        });
    };
    this.handleLoginRequest = (req, res, next) => {
        const { userName, password } = req.body;

        if (!userName || !password) {
            return res.render("login", {
                userName: "",
                password: "",
                loginError: "Username and password are required",
                environmentalScripts
            });
        }

        if (!validator.isAlphanumeric(userName.replace(/\s/g, ''))) {
            return res.render("login", {
                userName,
                password: "",
                loginError: "Invalid username format",
                environmentalScripts
            });
        }

        userDAO.validateLogin(userName, password, (err, user) => {
            if (err) {
                const errorType = err.noSuchUser ? "Invalid username" : 
                                err.invalidPassword ? "Invalid password" : 
                                "Login error";
                return res.render("login", {
                    userName,
                    password: "",
                    loginError: errorType,
                    environmentalScripts
                });
            }

            // JWT token generation
            const token = jwt.sign(
                { id: user._id, isAdmin: user.isAdmin },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
            );

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production'
            });

            res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
        });
    };
    this.displayLogoutPage = (req, res) => {
        res.clearCookie('token');
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
        errors.userNameError = "";
        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        if (!/^[a-zA-Z0-9]+$/.test(userName)) {
            errors.userNameError = "Username must be alphanumeric";
            return false;
        }

        if (!/^[a-zA-Z ]+$/.test(firstName) || !/^[a-zA-Z ]+$/.test(lastName)) {
            errors.firstNameError = "Names can only contain letters";
            return false;
        }

        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/;
        if (!strongPasswordRegex.test(password)) {
            errors.passwordError = "Password must be 8-20 chars with uppercase, lowercase, number & special char";
            return false;
        }

        if (password !== verify) {
            errors.verifyError = "Passwords must match";
            return false;
        }

        if (email && !validator.isEmail(email)) {
            errors.emailError = "Invalid email format";
            return false;
        }

        return true;
    };


    this.handleSignup = (req, res, next) => {
        const { userName, firstName, lastName, password, verify, email } = req.body;
        const errors = {
            userName, firstName, lastName, email,
            passwordError: "", verifyError: "",
            userNameError: "", emailError: ""
        };

        if (!validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            return res.render("signup", { ...errors, environmentalScripts });
        }

        userDAO.getUserByUserName(userName, (err, user) => {
            if (err) return next(err);
            if (user) {
                errors.userNameError = "Username already exists";
                return res.render("signup", { ...errors, environmentalScripts });
            }

            userDAO.addUser(userName, firstName, lastName, password, email, (err, user) => {
                if (err) return next(err);
                
                prepareUserData(user, next);
                
                const token = jwt.sign(
                    { id: user._id, isAdmin: user.isAdmin },
                    process.env.JWT_SECRET,
                    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
                );

                res.cookie('token', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production'
                });

                res.render("dashboard", {
                    ...user,
                    userId: user._id,
                    environmentalScripts
                });
            });
        });
    };

    this.displayWelcomePage = (req, res, next) => {
        if (!req.userId) return res.redirect("/login");
        
        userDAO.getUserById(req.userId, (err, user) => {
            if (err) return next(err);
            res.render("dashboard", {
                ...user,
                userId: user._id,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;



