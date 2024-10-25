const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

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
app.use(session({
    secret: 'nodesecret',
    resave: false,
    saveUninitialized: true
}))

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

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
            const user = result[0];
            if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.redirect('/home');
            } else {
                res.render('/login', { error_msg: 'Incorrect password!'});
            }
        } else {
            res.render('/login', { error_msg: 'User not found!' });
        }
    })
});


app.listen(3000, () => {
    console.log('Server is running...');
})