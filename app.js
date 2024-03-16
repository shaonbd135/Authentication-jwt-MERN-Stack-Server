require('dotenv').config;
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const User = require('./models/user.model');
const jwt = require('jsonwebtoken');
const passport = require('passport');
require('./config/database');
require('./config/passport');

const app = express();

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(passport.initialize());

//Home Route
app.get('/', (req, res) => {
    res.send('Authentication-jwt-MERN-Stack-Server Running');
})

//Register Route
app.post('/register', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const name = req.body.name;

    try {
        //checking if user exist or not
        const user = await User.findOne({
            username
        });
        if (user) return res.status(400).send('User Already Exist');

        //Encrypting Password by bcrypt
        bcrypt.hash(password, saltRounds, async (err, hash) => {
            const newUser = new User({
                name: name,
                username: username,
                password: hash,
            });
            //save user in database
            await newUser.save();
            res.send({
                success: true,
                message: 'User Created Successfully',
                user: {
                    name: newUser.name,
                    username: newUser.username,
                    id: newUser._id,
                }
            })
        });
    }
    catch (error) {
        res.status(500).send({
            success: false,
            message: 'User is not created',
            error: error
        });
    }
})

//login route

app.post('/login', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    try {
        const user = await User.findOne({
            username,
        })
        if (!user) {
            return res.status(401).send({
                success: false,
                message: 'User is not found'
            })
        }

        if (!bcrypt.compareSync(password, user.password)) {

            return res.status(401).send({
                success: false,
                message: "incorrect username or password"
            })
        }

        // using jsonwebtoken npm package
        const payload = {
            id: user._id,
            username: user.username
        }
        const secretKey = process.env.SECRET_KEY;
        const token = jwt.sign(payload, secretKey, {
            expiresIn: '2d',
        })
        return res.status(200).send({
            success: true,
            message: 'user logged in successfuly',
            token: "Bearer " + token
        })
    }
    catch (error) {
        res.send(error.message)

    }
})


//profile route protected

app.get('/profile', passport.authenticate('jwt', { session: false }),
    function (req, res) {
        return res.status(200).send({
            success: true,
            user: {
                id: req.user._id,
                username: req.user.username,
                name: req.user.name
            }
        })
    }
);


//Resourse Not Found
app.use((req, res, next) => {
    res.status(404).json({
        message: 'Route Not Found',
    })
})

//server Error

app.use((err, req, res, next) => {
    res.status(500).send(err.message)
})




module.exports = app;


