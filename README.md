# Google OAuth2 Authentication Plugin for Replit Web Applications

## Overview

This repository contains a complete production‑ready implementation of a Google OAuth2 authentication plugin designed for Replit‑hosted web applications

The plugin enables end‑users to sign in using their Google accounts and securely maintains sessions using JSON Web Tokens (JWT) stored as HTTP‑only cookies

It can be easily integrated into your Replit web app to provide secure authentication and to persist user information

## Features

- **Google OAuth2 Sign‑In/Sign‑Out**  
  Initiates the OAuth flow by redirecting users to the secure Google consent page and processes the callback to authenticate users

- **JWT Session Management**  
  Creates a JWT that includes key user details (email, full name, profile picture) and stores it in an HTTP‑only cookie to prevent client‑side access

- **Authenticated Endpoint**  
  Provides a protected `/me` endpoint that verifies the JWT and returns authenticated user information

- **Configurable Redirects**  
  Supports redirection after successful login using a configurable frontend URL set via environment variables or query parameters

- **Logout Functionality**  
  Implements a `/logout` endpoint which clears the JWT cookie, thereby terminating the session

## Requirements

- **Node.js (v14 or above)**  
  The plugin is built with Node.js and Express

- **Google API Credentials**  
  A Google OAuth Client ID, Client Secret, and a valid OAuth Redirect URI must be configured in the Google Cloud Console

- **Replit Environment**  
  Deployment on Replit using environment variable configuration for secure parameter management

## Installation

1. Clone the repository:
   `git clone <repository-url>`
   `cd replit-google-oauth-plugin`

2. Install the required dependencies:
   `npm install`

Configuration
Set the following environment variables in your Replit Secrets Panel:

GOOGLE_CLIENT_ID
Your Google OAuth Client ID

GOOGLE_CLIENT_SECRET
Your Google OAuth Client Secret

GOOGLE_REDIRECT_URI
The OAuth callback URL (e.g. https://<your-repl-name>.repl.co/auth/google/callback)

JWT_SECRET
A strong secret key used to sign the JWT

FRONTEND_URL (optional)
The URL to which users are redirected after authentication (defaults to / if not provided)

Usage Instructions

Running the Application
Start the application using Replit’s Run button or via the terminal:
`npm start`

The server will launch on the specified port (default is 3000), and the OAuth flow will be available at the defined endpoints

Endpoint Descriptions
/auth/google
Initiates the Google OAuth2 login flow by redirecting the user to Google’s authentication page

/auth/google/callback
Handles the OAuth callback, exchanges the authorization code for tokens, retrieves user profile data, generates a JWT, stores it in an HTTP‑only cookie, and redirects the user to the configured frontend URL

/me
A protected endpoint that verifies the JWT and returns the current user’s profile information

/logout
Clears the JWT cookie and ends the user session

Security Considerations
HTTP‑only Cookies:
The JWT is stored in an HTTP‑only cookie, reducing the risk of cross‑site scripting (XSS) attacks

HTTPS Enforcement:
Ensure that the application is deployed over HTTPS in production so that cookie security settings are effective

OAuth State Parameter:
A unique state parameter is generated during the OAuth flow to mitigate cross‑site request forgery (CSRF) attacks

JWT Expiration:
JWT tokens are issued with an expiration period (e.g. 1 day) to limit session duration and enhance security

Deployment
Configure your environment variables in the Replit Secrets Panel as described above

Commit your changes and deploy the application using Replit’s deployment features

Monitor application logs to verify that the OAuth flow, token generation, and session management operate correctly

Support and Contributions
For issues or feature requests, please open an issue in the GitHub repository

Contributions and pull requests are welcome to enhance the functionality or security of the plugin

License
This project is licensed under the MIT License

Contact Information
For further inquiries or support, please refer to the repository’s contact information or open an issue in the GitHub repository.