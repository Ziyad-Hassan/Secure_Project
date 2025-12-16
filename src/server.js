require('dotenv').config();
'use strict';

// 1. Imports
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const router = require('./router');
const bodyParser = require('body-parser');
const db = require('./orm');
const sjs = require('sequelize-json-schema');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const expressJSDocSwagger = require('express-jsdoc-swagger');
const expressNunjucks = require('express-nunjucks');
// const formidableMiddleware = require('express-formidable'); // Commented out to prevent conflict with body-parser/multer

// 2. Initialize App (Must be BEFORE using middleware)
const app = express();
const PORT = config.PORT;

// 3. Security Headers (Helmet) - Fixes Missing Headers
app.use(helmet({
    contentSecurityPolicy: false, // Disabled temporarily to allow external scripts (like buttons.js)
}));

// 4. Rate Limiting (Prevent Brute Force & DoS)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// 5. Body Parsers
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // Added to handle form data correctly

// 6. Session Configuration (Semgrep Fixes)
// Fix: Use Environment Variable or strong fallback, Enable httpOnly
const sessionSecret = process.env.SESSION_SECRET || 'long_random_secure_string_for_dev_only';

app.use(session({
    name: 'sessionId',
    secret: sessionSecret, // Fix: No hardcoded 'SuperSecret'
    resave: false,
    saveUninitialized: false, // Fix: Recommended for login sessions
    cookie: {
        httpOnly: true, // Fix: Mitigates XSS (Semgrep Requirement)
        secure: false,  // Set to TRUE if using HTTPS (Keep false for localhost)
        maxAge: 2 * 24 * 60 * 60 * 1000, // 2 days
        sameSite: 'lax' // CSRF Protection helper
    }
}));

app.use(cookieParser());

// 7. Static Files
app.use(express.static('src/public'));

// 8. Template Engine (Nunjucks)
app.set('views', __dirname + '/templates');
const njk = expressNunjucks(app, {
    watch: true,
    noCache: true
});

// 9. Routes
router(app, db);

// 10. Swagger Documentation
const docOptions = {
    info: {
        version: '1.0.0',
        title: 'Secure Node App',
        license: { name: 'MIT' },
    },
    security: {
        BearerAuth: { type: 'http', scheme: 'bearer' },
    },
    baseDir: __dirname,
    filesPattern: './../**/*.js',
    swaggerUIPath: '/api-docs',
    exposeSwaggerUI: true,
    exposeApiDocs: true,
    apiDocsPath: '/v1/api-docs',
    notRequiredAsNullable: false,
    swaggerUiOptions: {},
    multiple: true,
};
expressJSDocSwagger(app)(docOptions);

// Generate schemas from sequelize
const options = { exclude: ['id', 'createdAt', 'updatedAt'] };
sjs.getSequelizeSchema(db.sequelize, options);

// 11. Start Server
// drop and resync with { force: true } normal with alter:true
db.sequelize.sync({ alter: true }).then(() => {
    app.listen(PORT, () => {
        console.log('Express listening on port:', PORT);
    });
});