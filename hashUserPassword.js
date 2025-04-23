const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const dotenv = require('dotenv');
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// req => this holds everything coming from the client (postman, browser, etc.) when the send the request to the server. i can access things like req.body, req.params, req.query..etc.
// res => this is how i send back the data to the client. like res.send(), res.json(), res.status(201/404),... etc.


const users = [];

function findUser(username) {
    let user = "";
    let idx = 0; 
    for (user of users) {
            if (user.username == username) {
                return users[idx];
        }
        idx += 1;
    }
}

function createUser(username, password, role='user') {
    const hashed = bcrypt.hashSync(password, 10);
    users.push({username, password:hashed, role});
}


dotenv.config();
const app = express();
app.use(bodyParser.json());

const JWT_SECRECT = process.env.JWT_SECRECT;

// basic rate limit: 3 requests per minute per IP
const authLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 2,
    message: {msg: 'Too many requests, please try again later..'}
});

// register
app.post('/register', authLimiter, (req, res) => {
    const { username, password, role } =  req.body;

    if (findUser(username)) {
        return res.status(400).json({ msg: 'User aleardy exists!' })
    }
    
    createUser(username, password, role);

    return res.status(201).json({ msg: 'User registered successfully' });
})


// login
app.post('/login', authLimiter, (req, res) => {
    const { username, password } = req.body;

    const user = findUser(username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ msg: "invalid credntials"});
    }

    const token = jwt.sign({username, role:user.role}, JWT_SECRECT, {expiresIn:'1h'});
    return res.json({token});
});

// protected route (admin)
app.get('/admin-only', verifyToken, authorizeRoles('admin'), (req, res) => {{
    res.json({msg: `welcome ${req.user.username}, you are authorized as admin.`});
}});

// protected route (regular users and admins)
app.get('/user-or-admin', verifyToken, authorizeRoles('user', 'admin'), (req, res) => {
    res.json({msg: `Hello ${req.user.username}, this route is for users and admins.`})
});

// middleware to verify JWT
function verifyToken(req, res, next) {
    const bearer = req.headers['authorization'];

    if (!bearer || !bearer.startsWith('Bearer ')) {
        return res.status(401).json({msg:"Missing or invalid token"});
    }

    const token = bearer.split(" ")[1];

    try {
       const decoded = jwt.verify(token, JWT_SECRECT);
       req.user = decoded;
       next(); // to move to the next callback function in /protected 
    } catch (err) {
        res.status(403).json({ msg: 'Token is not valid' });
    }
}

// new middleware for user roles
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({msg: 'Access denied: insufficient permission.'});
        }
        next();
    };
}


// app listening port setup
app.listen(3000, () => console.log('Server is running!'))