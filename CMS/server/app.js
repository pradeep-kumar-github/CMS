require("dotenv").config({path: "./config/config.env"});
const express = require("express");
const morgan = require("morgan");

const connectDB = require("./config/db");

//defender of the route
const auth = require("./middlewares/auth")

const app = express();

//middlewares
app.use(express.json());
app.use(morgan("tiny"));

//routes
app.use("/api", require("./routes/auth"));

//server configurations
const PORT = process.env.PORT || 8000;
app.listen(PORT, async() => {
    try {
        await connectDB();
        console.log(`server listening on port: ${PORT}`);
    } catch (error) {
        console.log(error);   
    }
});
