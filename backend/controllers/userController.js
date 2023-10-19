const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

const nodemailer = require("nodemailer");

// @desc    Register new user
// @route   POST /api/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    res.status(400);
    throw new Error("All fields must be filled out");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(400).send("User already exists");
  }

  // Hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create user
  const user = await User.create({
    email,
    username,
    password: hashedPassword,
  });

  if (user) {
    // Send confirmation email
    sendConfirmationEmail(user.email);

    res.status(201).json({
      _id: user.id,
      username: user.username,
      email: user.email,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// Function to send a confirmation email
function sendConfirmationEmail(userEmail) {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: "opeafolabi5@gmail.com",
      pass: "vctzwszdksqkjcmn",
    },
  });

  const mailOptions = {
    from: "opeafolabi5@gmail.com",
    to: userEmail,
    subject: "Account Confirmation",
    text: "Thank you for registering. Your email address has been confirmed.",
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending confirmation email:", error);
    } else {
      console.log("Confirmation email sent: " + info.response);
    }
  });
}

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  // Check for user username
  const user = await User.findOne({ username });

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = generateToken(user._id);

    res.status(200).json({
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid credentials");
  }
});

// @desc    Get user profile
// @route   GET /api/profile
// @access  Private
const getUserProfile = asyncHandler(async (req, res) => {
  // Fetch the user's profile data from the currently authenticated user
  const user = await User.findById(req.user);
  if (user) {
    res.status(200).json({
      username: user.username,
      email: user.email,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

// @desc    Change user password
// @route   POST /api/actions/changepassword
// @access  Private
const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { old_password, new_password } = req.body;

    // Verify the current password
    const isPasswordValid = await bcrypt.compare(old_password, user.password);

    if (!isPasswordValid) {
      res.status(401);
      throw new Error("Current password is incorrect.");
    }

    // Hash and update the new password
    const newHashedPassword = await bcrypt.hash(new_password, 10);
    user.password = newHashedPassword;

    // Save the updated user with the new password
    await user.save();

    res.status(200).json({ message: "Password updated successfully." });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};

module.exports = {
  registerUser,
  loginUser,
  getUserProfile,
  changePassword,
};
