const bcrypt = require("bcrypt");
/* The UserDAO must be constructed with a connected database object */
function UserDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof UserDAO)) {
        console.log("Warning: UserDAO constructor called without 'new' operator");
        return new UserDAO(db);
    }

    // Store the collection reference properly on 'this'
    this.usersCol = db.collection("users");

    this.addUser = (userName, firstName, lastName, password, email, callback) => {
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        // Create user document
        const user = {
            userName,
            firstName,
            lastName,
            benefitStartDate: this.getRandomFutureDate(),
            password: hashedPassword
        };

        // Add email if set
        if (email) {
            user.email = email;
        }

        this.getNextSequence("userId", (err, id) => {
            if (err) return callback(err, null);
            
            user._id = id;
            this.usersCol.insertOne(user, (err, result) => {
                if (err) return callback(err, null);
                callback(null, result.ops[0]);
            });
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
        // Callback to pass to MongoDB that validates a user document
        const validateUserDoc = (err, user) => {
            if (err) return callback(err, null);

            if (!user) {
                const noSuchUserError = new Error("User does not exist");
                noSuchUserError.noSuchUser = true;
                return callback(noSuchUserError, null);
            }

            if (!bcrypt.compareSync(password, user.password)) {
                const invalidPasswordError = new Error("Invalid password");
                invalidPasswordError.invalidPassword = true;
                return callback(invalidPasswordError, null);
            }

            callback(null, user);
        };

        this.usersCol.findOne({ userName: userName }, validateUserDoc);
    };

    this.getUserById = (userId, callback) => {
        this.usersCol.findOne({ _id: parseInt(userId) }, callback);
    };

    this.getUserByUserName = (userName, callback) => {
        this.usersCol.findOne({ userName: userName }, callback);
    };

    this.getNextSequence = (name, callback) => {
        db.collection("counters").findAndModify(
            { _id: name },
            [],
            { $inc: { seq: 1 } },
            { new: true },
            (err, data) => {
                if (err) return callback(err, null);
                callback(null, data.value.seq);
            }
        );
    };
}

module.exports = { UserDAO };