require('dotenv').config();
"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const consolidate = require("consolidate");
const swig = require("swig");
const MongoClient = require("mongodb").MongoClient;
const http = require("http");
const marked = require("marked");
const { port, db, cookieSecret } = require("./config/config");
const routes = require("./app/routes");

// Winston Logger Setup
const winston = require("winston");
const logger = winston.createLogger({
    level: 'info',
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

MongoClient.connect(db, (err, db) => {
    if (err) {
        logger.error("Error: DB connection failed", err);
        process.exit(1);
    }
    logger.info("Connected to the database");

    const app = express();

    // Add favicon
    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Middleware
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: false }));

    app.use(session({
        secret: cookieSecret,
        saveUninitialized: true,
        resave: true
    }));

    // Logger for HTTP requests
    app.use((req, res, next) => {
        logger.info(`${req.method} ${req.url} - ${new Date().toISOString()}`);
        next();
    });

    // Template engine setup
    app.engine(".html", consolidate.swig);
    app.set("view engine", "html");
    app.set("views", `${__dirname}/app/views`);

    // Static assets
    app.use(express.static(`${__dirname}/app/assets`));

    // Marked setup for markdown rendering
    marked.setOptions({
        sanitize: true
    });
    app.locals.marked = marked;

    // Define app routes
    routes(app, db);

    // Swig config
    swig.setDefaults({
        autoescape: false
    });

    // Start HTTP server
    http.createServer(app).listen(port, () => {
        logger.info(`Express HTTP server listening on port ${port}`);
    });
/*
    
    // For HTTPS
    const fs = require("fs");
    const https = require("https");
    const path = require("path");
    const httpsOptions = {
        key: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.key")),
        cert: fs.readFileSync(path.resolve(__dirname, "./artifacts/cert/server.crt"))
    };
    https.createServer(httpsOptions, app).listen(port, () => {
        logger.info(`Express HTTPS server listening on port ${port}`);
    });
    */
    
});
