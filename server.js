"use strict";

// === Required Modules ===
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const consolidate = require("consolidate");
const swig = require("swig");
const MongoClient = require("mongodb").MongoClient;
const http = require("http");
const marked = require("marked");
const winston = require("winston");
const routes = require("./app/routes");

const cookieParser = require('cookie-parser');
const csrf = require('csurf');


const app = express();

require("dotenv").config();

const { db, cookieSecret } = require("./config/config");
const port = process.env.PORT || 4000;


// === Create Express App Early ===


// === Security Middleware ===
app.use(helmet());

// Content Security Policy
app.use(helmet.contentSecurityPolicy({
  useDefaults: true,
  directives: {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
  }
}));

// HTTP Strict Transport Security (HSTS)
app.use(helmet.hsts({
  maxAge: 63072000,
  includeSubDomains: true,
  preload: true
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// === CORS Setup ===
const allowedOrigins = ['http://localhost:4000'];
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// === Logger Setup ===
const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

require('dotenv').config(); // Load .env values

// Middleware to check API key in headers
function checkApiKey(req, res, next) {
  const userKey = req.headers['x-api-key'];

  if (!userKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  if (userKey !== process.env.API_KEY) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  next(); // API key is valid
}
app.get('/api/data', checkApiKey, (req, res) => {
  res.json({ message: 'Secure data accessed with valid API key.' });
});


// Middleware setup
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(csrf({ cookie: true }));

// Set view engine agar EJS ya HTML file use karo
app.set('view engine', 'ejs');

// CSRF Token wala form show karna
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// Form submit route
app.post('/process', (req, res) => {
  res.send('Form data processed successfully!');
});



// === Connect to MongoDB ===
MongoClient.connect(db, (err, dbClient) => {
  if (err) {
    logger.error("Error: DB connection failed", err);
    process.exit(1);
  }
  logger.info("Connected to the database");

  // === Static and Middleware Config ===
  app.use(favicon(__dirname + "/app/assets/favicon.ico"));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));

  app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true
  }));

  // HTTP Request Logging
  app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url} - ${new Date().toISOString()}`);
    next();
  });

  // Template Engine (Swig)
  app.engine(".html", consolidate.swig);
  app.set("view engine", "html");
  app.set("views", `${__dirname}/app/views`);

  // Static Assets
  app.use(express.static(`${__dirname}/app/assets`));

  // Markdown with Marked
  marked.setOptions({
    sanitize: true
  });
  app.locals.marked = marked;

  // Define Routes
  routes(app, dbClient);

  // Swig Configuration
  swig.setDefaults({
    autoescape: false
  });

  // === Start Server ===
  http.createServer(app).listen(port, () => {
    logger.info(`Express HTTP server listening on port ${port}`);
  });
});
