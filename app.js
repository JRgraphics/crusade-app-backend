// require("dotenv").config();

// getPgVersion();

import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import axios from "axios";
import cors from "cors";
import querystring from "querystring";
import cookieParser from "cookie-parser";

dotenv.config();

import { neon } from "@neondatabase/serverless";
const { PGHOST, PGDATABASE, PGUSER, PGPASSWORD } = process.env;
const sql = neon(
  `postgresql://${PGUSER}:${PGPASSWORD}@${PGHOST}/${PGDATABASE}?sslmode=require`
);

const port = 4000;

const app = express();

app.use(
  cors({
    // Sets Access-Control-Allow-Origin to the UI URI
    origin: process.env.UI_ROOT_URI,
    // Sets Access-Control-Allow-Credentials to true
    credentials: true,
  })
);

app.use(cookieParser());

const redirectURI = "auth/google";

function getGoogleAuthURL() {
  const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
  const options = {
    redirect_uri: `${process.env.SERVER_ROOT_URI}/${redirectURI}`,
    client_id: process.env.GOOGLE_CLIENT_ID,
    access_type: "offline",
    response_type: "code",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ].join(" "),
  };

  return `${rootUrl}?${querystring.stringify(options)}`;
}

// Getting login URL
app.get("/auth/google/url", (req, res) => {
  return res.send(getGoogleAuthURL());
});

function getTokens({ code, clientId, clientSecret, redirectUri }) {
  /*
   * Uses the code to get tokens
   * that can be used to fetch the user's profile
   */
  const url = "https://oauth2.googleapis.com/token";
  const values = {
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  };

  return axios
    .post(url, querystring.stringify(values), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    })
    .then((res) => res.data)
    .catch((error) => {
      console.error(`Failed to fetch auth tokens`);
      throw new Error(error.message);
    });
}

// Getting the user from Google with the code
app.get(`/${redirectURI}`, async (req, res) => {
  const code = req.query.code;

  const { id_token, access_token } = await getTokens({
    code,
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: `${process.env.SERVER_ROOT_URI}/${redirectURI}`,
  });

  // Fetch the user's profile with the access token and bearer
  const googleUser = await axios
    .get(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${access_token}`,
      {
        headers: {
          Authorization: `Bearer ${id_token}`,
        },
      }
    )
    .then((res) => res.data)
    .catch((error) => {
      console.error(`Failed to fetch user`);
      throw new Error(error.message);
    });

  const token = jwt.sign(googleUser, process.env.JWT_SECRET);

  res.cookie(process.env.COOKIE_NAME, token, {
    maxAge: 900000,
    httpOnly: true,
    secure: process.env.ENVIRONMENT === "dev" ? false : true,
  });

  res.redirect(process.env.UI_ROOT_URI);
});

// Getting the current user
app.get("/auth", async (req, res) => {
  try {
    console.log(req.headers);
    console.log(req.headers["authorization"]);
    const decoded = jwt.verify(
      req.headers["authorization"],
      process.env.JWT_SECRET
    );
    const result =
      await sql`SELECT * FROM army_lists WHERE owner=${decoded.email}`;
    return res.send(result[0]);
  } catch (err) {
    console.log(err);
    res.status(403).send(getGoogleAuthURL());
  }
});

function main() {
  app.listen(port, () => {
    console.log(`App listening http://localhost:${port}`);
  });
}

main();
