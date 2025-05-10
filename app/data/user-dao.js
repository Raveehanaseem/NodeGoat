const bcrypt = require("bcrypt-nodejs");
const validator = require('validator');

/* The UserDAO must be constructed with a connected database object */
function UserDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof UserDAO)) {
        console.log("Warning: UserDAO constructor called without 'new' operator");
        return new UserDAO(db);
    }

    const usersCol = db.collection("users");

    this.addUser = (userName, firstName, lastName, password, email, callback) => {
        // Sanitize inputs
        const sanitizedUserName = validator.escape(userName.trim());
        const sanitizedFirstName = validator.escape(firstName.trim());
        const sanitizedLastName = validator.escape(lastName.trim());
        const sanitizedEmail = email ? validator.normalizeEmail(email.trim()) : null;
        
        // Create user document
        const user = {
            userName: sanitizedUserName,
            firstName: sanitizedFirstName,
            lastName: sanitizedLastName,
            benefitStartDate: this.getRandomFutureDate(),
            // Fix for A2-1 - Broken Auth
            // Stores password in a safer way using one way encryption and salt hashing
            password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
        };

        // Add email if set
        if (sanitizedEmail) {
            user.email = sanitizedEmail;
        }

        this.getNextSequence("userId", (err, id) => {
            if (err) {
                return callback(err, null);
            }

            user._id = id;
            usersCol.insert(user, (err, result) => !err ? callback(null, result.ops[0]) : callback(err, null));
        });
    };

    this.getRandomFutureDate = () => {
        const today = new Date();
        const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
        const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
        const year = Math.ceil(Math.random() * 30) + today.getFullYear();
        return `${year}-${("0" + month).slice(-2)}-${("0" + day).slice(-2)}`;
    };

    this.validateLogin = (userName, password, callback) => {
        // Sanitize input
        const sanitizedUserName = validator.escape(userName.trim());

        // Helper function to compare passwords
        const comparePassword = (fromUser, fromDB) => {
            try {
                // Check if the stored password is a bcrypt hash
                if (fromDB && fromDB.startsWith('$2')) {
                    // It's already a bcrypt hash, use compareSync
                    return bcrypt.compareSync(fromUser, fromDB);
                } else {
                    // It's still a plaintext password (during transition)
                    return fromUser === fromDB;
                }
            } catch (e) {
                console.log("Password comparison error:", e.message);
                // Fall back to direct comparison if bcrypt fails
                return fromUser === fromDB;
            }
        };

        // Callback to pass to MongoDB that validates a user document
        const validateUserDoc = (err, user) => {
            if (err) return callback(err, null);

            if (user) {
                if (comparePassword(password, user.password)) {
                    // If password is still plaintext, hash it now for future logins
                    if (!user.password.startsWith('$2')) {
                        // Hash and update the password for next time
                        const hashedPassword = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
                        usersCol.updateOne(
                            { _id: user._id },
                            { $set: { password: hashedPassword } },
                            (updateErr) => {
                                if (updateErr) console.log("Error updating password hash:", updateErr);
                            }
                        );
                    }
                    callback(null, user);
                } else {
                    const invalidPasswordError = new Error("Invalid password");
                    // Set an extra field so we can distinguish this from a db error
                    invalidPasswordError.invalidPassword = true;
                    callback(invalidPasswordError, null);
                }
            } else {
                const noSuchUserError = new Error("User does not exist");
                // Set an extra field so we can distinguish this from a db error
                noSuchUserError.noSuchUser = true;
                callback(noSuchUserError, null);
            }
        };

        usersCol.findOne({
            userName: sanitizedUserName
        }, validateUserDoc);
    };

    this.getUserById = (userId, callback) => {
        // Validate userId is a number to prevent injection
        const numericUserId = parseInt(userId, 10);
        if (isNaN(numericUserId)) {
            return callback(new Error("Invalid user ID format"), null);
        }
        
        usersCol.findOne({
            _id: numericUserId
        }, callback);
    };

    this.getUserByUserName = (userName, callback) => {
        // Sanitize input
        const sanitizedUserName = validator.escape(String(userName).trim());
        
        usersCol.findOne({
            userName: sanitizedUserName
        }, callback);
    };

    this.getNextSequence = (name, callback) => {
        // Validate sequence name
        const validSequenceName = validator.escape(String(name).trim());
        
        db.collection("counters").findAndModify({
                _id: validSequenceName
            }, [], {
                $inc: {
                    seq: 1
                }
            }, {
                new: true
            },
            (err, data) => err ? callback(err, null) : callback(null, data.value.seq));
    };
}

module.exports = { UserDAO };