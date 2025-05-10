const UserDAO = require("../data/user-dao").UserDAO;
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const ESAPI = require('node-esapi');

/* The SessionHandler must be constructed with a connected db */
function SessionHandler(db) {
    "use strict";

    const userDAO = new UserDAO(db);
    const allocationsDAO = new AllocationsDAO(db);
    const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-should-be-in-env-variables";

    const prepareUserData = (user, next) => {
        // Generate random allocations
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
        console.log("redirecting to login");
        return res.redirect("/login");
    };

    this.isLoggedInMiddleware = (req, res, next) => {
        if (req.session.userId) {
            return next();
        }
        console.log("redirecting to login");
        return res.redirect("/login");
    };

    // Middleware to verify JWT token
    this.verifyToken = (req, res, next) => {
        const token = req.headers['x-access-token'] || req.headers['authorization'];
        
        if (!token) {
            return res.status(403).send({ auth: false, message: 'No token provided.' });
        }
        
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
            }
            
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
        let {
            userName,
            password
        } = req.body;
        
        // Sanitize inputs
        if (userName) {
            userName = validator.escape(userName.trim());
        }
        
        // Validate inputs
        if (!userName || !password) {
            return res.render("login", {
                userName: userName || "",
                password: "",
                loginError: "Username and password are required",
                environmentalScripts
            });
        }

        userDAO.validateLogin(userName, password, (err, user) => {
            const errorMessage = "Invalid username and/or password";
            
            if (err) {
                if (err.noSuchUser || err.invalidPassword) {
                    // Log sanitized username to prevent log injection
                    console.log("Login error: %s", 
                        ESAPI.encoder().encodeForHTML(userName).replace(/(\r\n|\r|\n)/g, '_'));

                    return res.render("login", {
                        userName: userName,
                        password: "",
                        // Use identical error message for both cases to prevent username enumeration
                        loginError: errorMessage,
                        environmentalScripts
                    });
                } else {
                    return next(err);
                }
            }

            // Regenerate session to prevent session fixation attacks
            req.session.regenerate((err) => {
                if (err) return next(err);
                
                req.session.userId = user._id;
                
                // Create JWT token for API authentication
                const token = jwt.sign({ id: user._id }, JWT_SECRET, {
                    expiresIn: 86400 // expires in 24 hours
                });
                
                // Store token in a secure HTTP-only cookie
                res.cookie('auth_token', token, { 
                    httpOnly: true, 
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict'
                });
                
                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
            });
        });
    };

    this.displayLogoutPage = (req, res) => {
        req.session.destroy(() => {
            res.clearCookie('auth_token');
            res.redirect("/");
        });
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
        const USER_RE = /^[a-zA-Z0-9_]{3,20}$/; // More restrictive username regex
        const FNAME_RE = /^[a-zA-Z- ]{1,100}$/;
        const LNAME_RE = /^[a-zA-Z- ]{1,100}$/;
        const EMAIL_RE = /^[\S]+@[\S]+\.[\S]+$/;
        // Fix for A2-2 - Broken Authentication - requires stronger password
        // At least 8 characters with numbers and both lowercase and uppercase letters
        const PASS_RE = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;

        errors.userNameError = "";
        errors.firstNameError = "";
        errors.lastNameError = "";
        errors.passwordError = "";
        errors.verifyError = "";
        errors.emailError = "";

        // Validate username
        if (!USER_RE.test(userName)) {
            errors.userNameError = "Invalid username. Use 3-20 alphanumeric characters or underscores.";
            return false;
        }
        
        // Validate first name
        if (!FNAME_RE.test(firstName)) {
            errors.firstNameError = "Invalid first name.";
            return false;
        }
        
        // Validate last name
        if (!LNAME_RE.test(lastName)) {
            errors.lastNameError = "Invalid last name.";
            return false;
        }
        
        // Validate password strength
        if (!PASS_RE.test(password)) {
            errors.passwordError = "Password must be at least 8 characters" +
                " including numbers, lowercase and uppercase letters.";
            return false;
        }
        
        // Verify passwords match
        if (password !== verify) {
            errors.verifyError = "Passwords must match";
            return false;
        }
        
        // Validate email if provided
        if (email !== "") {
            if (!EMAIL_RE.test(email)) {
                errors.emailError = "Invalid email address";
                return false;
            }
        }
        
        return true;
    };

    this.handleSignup = (req, res, next) => {
        // Sanitize inputs
        const userName = validator.escape(req.body.userName?.trim() || "");
        const firstName = validator.escape(req.body.firstName?.trim() || "");
        const lastName = validator.escape(req.body.lastName?.trim() || "");
        const email = validator.normalizeEmail(req.body.email?.trim() || "");
        const password = req.body.password || "";
        const verify = req.body.verify || "";

        // set these up in case we have an error case
        const errors = {
            "userName": userName,
            "firstName": firstName,
            "lastName": lastName,
            "email": email
        };

        if (validateSignup(userName, firstName, lastName, password, verify, email, errors)) {
            userDAO.getUserByUserName(userName, (err, user) => {
                if (err) return next(err);

                if (user) {
                    errors.userNameError = "Username already in use. Please choose another";
                    return res.render("signup", {
                        ...errors,
                        environmentalScripts
                    });
                }

                userDAO.addUser(userName, firstName, lastName, password, email, (err, user) => {
                    if (err) return next(err);

                    // Prepare data for the user
                    prepareUserData(user, next);
                    
                    // Regenerate session to prevent session fixation attacks
                    req.session.regenerate((err) => {
                        if (err) return next(err);
                        
                        req.session.userId = user._id;
                        // Set userId property. Required for left nav menu links
                        user.userId = user._id;
                        
                        // Create JWT token for API authentication
                        const token = jwt.sign({ id: user._id }, JWT_SECRET, {
                            expiresIn: 86400 // expires in 24 hours
                        });
                        
                        // Store token in a secure HTTP-only cookie
                        res.cookie('auth_token', token, { 
                            httpOnly: true, 
                            secure: process.env.NODE_ENV === 'production',
                            sameSite: 'strict'
                        });

                        return res.render("dashboard", {
                            ...user,
                            environmentalScripts
                        });
                    });
                });
            });
        } else {
            console.log("User did not validate");
            return res.render("signup", {
                ...errors,
                environmentalScripts
            });
        }
    };

    this.displayWelcomePage = (req, res, next) => {
        let userId;

        if (!req.session.userId) {
            console.log("welcome: Unable to identify user...redirecting to login");
            return res.redirect("/login");
        }

        userId = req.session.userId;

        userDAO.getUserById(userId, (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;
            return res.render("dashboard", {
                ...doc,
                environmentalScripts
            });
        });
    };
}

module.exports = SessionHandler;