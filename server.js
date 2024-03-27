require('dotenv').config(); // Load environment variables

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const http = require('http');
const socketIo = require('socket.io');
const User = require('./models/User'); // Ensure this model is correctly defined

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

mongoose.connect(process.env.DATABASE_URI) // Connect to MongoDB
  .then(() => console.log('MongoDB connected...'))
  .catch(err => console.log(err));

const sessionMiddleware = session({ // Session setup
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.DATABASE_URI })
});
app.use(sessionMiddleware);

// Passport setup for authentication
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy( // Passport Local Strategy for username and password
    async (username, password, done) => {
        try {
            const user = await User.findOne({ username: username });
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Incorrect password.' });
            }
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user); // Success: pass the user to the next middleware
    } catch (error) {
        done(error); // Error: pass the error to the next middleware
    }
});

app.use(express.static('public')); // Serve static files

// Routes
app.get('/', (req, res) => { res.sendFile(__dirname + '/index.html'); }); // Main page

app.get('/login', (req, res) => { res.sendFile(__dirname + '/public/login.html'); }); // Login page
app.get('/register', (req, res) => { res.sendFile(__dirname + '/public/register.html'); }); // Registration page

app.post('/register', async (req, res) => { // Registration handling
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({ username: req.body.username, password: hashedPassword });
        await user.save();
        res.redirect('/login');
    } catch (error) {
        res.status(500).send('Error registering new user: ' + error.message);
    }
});

app.post('/login', passport.authenticate('local', { // Login handling
    successRedirect: '/chat',
    failureRedirect: '/login',
    failureFlash: false
}));

app.get('/logout', (req, res) => { // Logout handling
    req.logout(() => {
        res.redirect('/');
    });
});

app.get('/chat', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(__dirname + '/public/chat.html');
    } else {
        res.redirect('/login');
    }
});


// Socket.IO with shared session middleware
io.use((socket, next) => { sessionMiddleware(socket.request, {}, next); });
io.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('chat message', (msg) => {
        console.log('message: ' + msg);

        io.emit('chat message', msg); // This should broadcast the message to all connected clients
    });

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => { console.log(`Server running on port ${PORT}`); });
