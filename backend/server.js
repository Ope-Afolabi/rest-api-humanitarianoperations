const express = require("express");
require("dotenv").config();
const connectDB = require("./config/db");
const { errorHandler } = require("./middleware/errorMiddleware");
const port = process.env.PORT || 5000;
const path = require("path");

connectDB();

const app = express();

app.use(errorHandler);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use("/api", require("./routes/userRoutes"));

app.listen(port, () => console.log(`Server started on port ${port}`));
