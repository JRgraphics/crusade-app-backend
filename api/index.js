require("dotenv").config();
const express = require("express");
const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sql = require("./dbaccess");

const app = express();
const PORT = 3000;
const client = new OAuth2Client();
const JWT_SECRET = process.env.JWT_SECRET;
const corsOptions = {
  origin: "http://localhost:5173",
  credentials: true,
};

app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());

app.post("/auth/google", async (req, res) => {
  const { authorization } = req.headers;
  const { clientId } = req.body;
  const client_id = clientId;
  let auth_token = null;
  try {
    const secret = jwt.verify(
      req.headers["authorization"],
      process.env.JWT_SECRET
    );
    auth_token = secret.auth_token;
  } catch (error) {
    auth_token = null;
  }

  console.log(auth_token);

  try {
    // Verify the ID token with Google's API

    console.log(authorization);

    const ticket = await client.verifyIdToken({
      idToken: auth_token || authorization,
      audience: client_id,
    });
    const payload = ticket.getPayload();

    const { email, given_name, family_name } = payload;

    // Create a new user if they don't exist
    const user = {
      email,
      name: `${given_name} ${family_name}`,
      authSource: "google",
    };

    // Generate a JWT token
    const token = jwt.sign(
      { email: user.email, auth_token: authorization },
      JWT_SECRET,
      {
        expiresIn: "1d", // Adjust expiration time as needed
      }
    );

    // Send the token as a cookie and response
    const result = await sql`SELECT * from army_lists WHERE owner=${email}`;
    console.log(result[0]);
    res
      .status(200)
      .cookie(process.env.COOKIE_NAME, token, {
        httpOnly: false,
        sameSite: "Strict",
        secure: false, // Set to true in production when using HTTPS
        maxAge: 86400000, // 1 day in milliseconds
      })
      .json({ message: "Authentication successful", user });
  } catch (err) {
    console.log(err);
    res.status(400).json({ error: "Authentication failed", details: err });
  }
});

app.listen(PORT, () => console.log(`Server running on PORT : ${PORT}`));

module.exports = app;
