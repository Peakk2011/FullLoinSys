const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const validator = require('validator');

const app = express();

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'nodejs_login'
})

db.connect((err) => {
    if (err) {
        throw err;
    } 

    console.log('MySQL Connected...');
})

// Setup middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')))
app.use(helmet());
app.use(csrf({ cookie: false }));

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts
    message: 'Too many login attempts, please try again after 15 minutes'
});

// Update session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'nodesecret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 2, // 2 hours
        sameSite: 'strict'
    }
}));

// Set EJS as template engine
app.set('view engine', 'ejs');

// Middleware to check if the user is logged in
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    } else {
        res.redirect('/login');
    }
}

function ifLoggedIn(req, res, next) {
    if (req.session.user) {
        return res.redirect('/home');
    }
    next();
}

// GET Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
})

app.get('/login', ifLoggedIn, (req, res) => {
    res.render('login');
})

app.get('/register', ifLoggedIn, (req, res) => {
    res.render('register');
})

app.get('/home', isAuthenticated, (req, res) => {
    console.log(req.session.user);
    res.render('home', { user: req.session.user });
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

// POST Routes
app.post('/register', (req, res) => {
    const { name, email, password } = req.body;

    const checkEmailQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkEmailQuery, [email], (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
            // Check if email already exists
            res.render('register', { error_msg: 'Email already registered. Please use a different email.'})
        } else {
            const hashedPassword = bcrypt.hashSync(password, 10);
            const insertUserQuery = 'INSERT INTO users (name, email, password) VALUES(?, ?, ?)';
            db.query(insertUserQuery, [name, email, hashedPassword], (err, result) => {
                if (err) throw err;
                res.render('register', { success_msg: 'Registration successfully!'})
            })
        }
    });
})

app.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
        return res.render('login', { error_msg: 'All fields are required' });
    }

    if (!validator.isEmail(email)) {
        return res.render('login', { error_msg: 'Invalid email format' });
    }

    if (password.length < 8) {
        return res.render('login', { error_msg: 'Password must be at least 8 characters' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.render('login', { error_msg: 'An error occurred' });
        }

        if (result.length > 0) {
            const user = result[0];
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                    console.error('Bcrypt error:', err);
                    return res.render('login', { error_msg: 'An error occurred' });
                }

                if (isMatch) {
                    // Don't store sensitive information in session
                    req.session.user = {
                        id: user.id,
                        name: user.name,
                        email: user.email
                    };
                    return res.redirect('/home');
                }
                return res.render('login', { error_msg: 'Invalid credentials' });
            });
        } else {
            // Use same message as invalid password to prevent user enumeration
            return res.render('login', { error_msg: 'Invalid credentials' });
        }
    });
});

// Add CSRF token to all responses
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

app.listen(3000, () => {
    console.log('Server is running...');
})