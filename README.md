# Auth DO POC

A proof-of-concept authentication system built with Cloudflare Workers and Durable Objects. This project demonstrates a scalable, distributed authentication system using Cloudflare's edge computing platform.

## Architecture

The system uses Durable Objects (DOs) for user data storage, with a clever partitioning strategy:

- Each user has two DOs:
  1. Email-based DO: Used for login lookups
  2. ID-based DO: Used for authenticated session data

This dual-DO approach provides:
- Fast email-based lookups for login
- Secure ID-based access for authenticated routes
- Natural horizontal scaling
- No central database or lookup table

## Features

- 🔐 Secure password hashing using WebCrypto API
- 🍪 HTTP-only cookie-based JWT authentication
- 📧 Email-based user lookup
- 🔄 Automatic session management
- 🚀 Edge-based authentication
- 📈 Horizontally scalable architecture

## Tech Stack

- Cloudflare Workers
- Durable Objects
- Hono (Web Framework)
- JWT for session tokens
- WebCrypto API for password hashing

## Security Features

- PBKDF2 password hashing with 100k iterations
- HTTP-only cookies
- Secure cookie settings
- JWT-based session management
- No password storage in cookies

## Getting Started

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Set up your environment variables:
   ```bash
   JWT_SECRET=your-secret-here
   ```
4. Run locally:
   ```bash
   npm run dev
   ```

## API Endpoints

- `GET /signup` - Signup page
- `POST /signup` - Create new account
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `GET /` - Protected profile page
- `POST /logout` - End session

## How It Works

1. **Signup**:
   - User submits email/password
   - System creates two DOs (email-based and ID-based)
   - Returns JWT token in HTTP-only cookie

2. **Login**:
   - User submits email/password
   - System looks up user by email DO
   - Verifies password hash
   - Returns JWT token in HTTP-only cookie

3. **Protected Routes**:
   - System verifies JWT token
   - Looks up user data by ID DO
   - Returns protected content

## Why Durable Objects?

Durable Objects provide:
- Strong consistency
- Low latency
- Automatic scaling
- No database management
- Built-in state management

This makes them perfect for:
- User session management
- Authentication state
- Distributed user data
- Edge-based authentication
