const mongoose = require('mongoose');
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const flightsRouter = require('./routes/flights');
const authRouter = require('./routes/auth');
const cookieParser = require('cookie-parser');

dotenv.config();

mongoose
.connect(process.env.MONGODB_URI)
.then(() => console.log("Connected to MongoDB Atlas"))
.catch((err) =>
console.error("MongoDB connection error:", err));


const app = express();
app.use(cors({
    origin: 'https://frontend-five-theta-28.vercel.app',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use('/flights', flightsRouter);
app.use('/api/auth', authRouter); 


app.listen(process.env.PORT || 4000, () => {
console.log('REST API running at http://localhost:4000');
});