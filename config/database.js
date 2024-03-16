const mongoose = require('mongoose');
require('dotenv').config();

mongoose.connect(process.env.MONGO_URL)
    .then(() => {
        console.log('MongoDB Connected');
    })
    .catch((error) => {
        console.log(error.message);
        process.exit(1);
    })