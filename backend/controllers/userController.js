// Importing necessary modules and files
import User from "../models/userModel.js"; // Importing the User model
import asyncHandler from "../middlewares/asyncHandler.js"; // Importing asyncHandler middleware
import bcrypt from "bcrypt"; // Importing bcrypt for password hashing
import createToken from "../utils/createToken.js"; // Importing createToken function to generate JWT tokens

// Define a function to create a new user
const createUser = asyncHandler(async (req, res) => {
  // Extracting username, email, and password from the request body
  const { username, email, password } = req.body;

  // Check if any required fields are missing
  if (!username || !email || !password) {
    throw new Error("Please fill all inputs");
  }

  // Check if the user already exists in the database by email
  const userExists = await User.findOne({ email });

  // If user already exists, send a 400 status with a message
  if (userExists) {
    res.status(400).send("User already exists");
  }

  // Generate a salt and hash the password using bcrypt
  const salt = await bcrypt.genSalt(10); // Generating a salt with 10 rounds
  const hashedPassword = await bcrypt.hash(password, salt); // Hashing the password

  // Create a new user object with the hashed password
  const newUser = new User({ username, email, password: hashedPassword });

  try {
    // Save the new user to the database
    await newUser.save();

    // Generate and set JWT token as an HTTP-only cookie
    createToken(res, newUser._id);

    // If user creation is successful, send a 201 status with user data
    res.status(201).json({
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      isAdmin: newUser.isAdmin,
    });
  } catch (error) {
    // If there's an error while saving the user, send a 400 status with an error message
    res.status(400);
    throw new Error("Invalid user data");
  }
});

// Define a function to login a user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find the user by email in the database
  const existingUser = await User.findOne({ email });

  // If user exists, proceed with password validation
  if (existingUser) {
    // Compare the provided password with the hashed password stored in the database
    const isPasswordValid = await bcrypt.compare(
      password,
      existingUser.password
    );

    // If the password is valid, generate and set JWT token as an HTTP-only cookie
    if (isPasswordValid) {
      createToken(res, existingUser._id);

      // Send a 201 status with user data if login is successful
      res.status(201).json({
        _id: existingUser._id,
        username: existingUser.username,
        email: existingUser.email,
        isAdmin: existingUser.isAdmin,
      });
      return; // Exit the function after sending the response
    }
  }
});

const logoutCurrentUser = asyncHandler(async (req, res) => {
  res.cookie("jwt", "", {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: "Logged out successfully" });
});

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find({});
  res.json(users);
});

const getCurrentUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    res.json({
      _id: user._id,
      username: user.username,
      email: user.email,
    });
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
});

const updateCurrentUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;

    if (req.body.password) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
      user.password = hashedPassword;
    }

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const deleteUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user) {
    if (user.isAdmin) {
      res.status(400);
      throw new Error("Cannot delete admin user");
    }

    await User.deleteOne({ _id: user._id });
    res.json({ message: "User removed" });
  } else {
    res.status(404);
    throw new Error("User not found.");
  }
});

const getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select("-password");

  if (user) {
    res.json(user);
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const updateUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id);

  if (user) {
    user.username = req.body.username || user.username;
    user.email = req.body.email || user.email;
    user.isAdmin = Boolean(req.body.isAdmin);

    const updatedUser = await user.save();

    res.json({
      _id: updatedUser._id,
      username: updatedUser.username,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

// Export the createUser and loginUser functions
export {
  createUser,
  loginUser,
  logoutCurrentUser,
  getAllUsers,
  getCurrentUserProfile,
  updateCurrentUserProfile,
  deleteUserById,
  getUserById,
  updateUserById,
};
