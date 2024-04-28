// Importing the jwt module for JSON Web Token generation
import jwt from "jsonwebtoken";

// Define a function to generate a JWT token and set it as an HTTP-only cookie
const generateToken = (res, userId) => {
  // Generate a JWT token using jwt.sign() method
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "30d", // Token expires in 30 days
  });

  // Set the JWT token as an HTTP-only cookie in the response
  res.cookie("jwt", token, {
    httpOnly: true, // Cookie accessible only by the server, not by client-side scripts
    secure: process.env.NODE_ENV != "development", // Set 'secure' to true in production environment
    sameSite: "strict", // Ensure that the cookie is only sent with requests from the same site
    maxAge: 30 * 24 * 60 * 60 * 1000, // Maximum age of the cookie (30 days in milliseconds)
  });

  // Return the generated token
  return token;
};

// Export the generateToken function to be used in other parts of the application
export default generateToken;
