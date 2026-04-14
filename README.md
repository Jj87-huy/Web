# Web

A Node.js + Express web application that implements a basic authentication system with CSRF protection and filesystem-based user storage.

---

## 🧩 Overview

This project is a simple web server built with **Express.js** that serves static content and provides secure authentication APIs (`register`, `login`, `logout`, `profile`). It is designed to demonstrate secure session handling using cookies, CSRF mitigation, and safe filesystem operations for user data.

The server:

- Serves static HTML/CSS/JS from the `public` directory
- Implements secure authentication endpoints under `/api/auth`
- Uses JSON Web Tokens (JWT) stored in HttpOnly cookies
- Applies CSRF protection to state-changing requests
- Stores user accounts and indexes in a simple file-based data structure

---

## 📦 Features

**Authentication**

- User registration with:
  - Username validation
  - Email validation
  - Strong password policy enforcement
  - Atomic file writes to avoid corruption
- User login with:
  - Brute-force protection
  - JWT generation with expiration
  - Secure cookie storage
- Logout and profile retrieval endpoints

**Security**

- CSRF token generation and validation middleware
- Helmet for secure HTTP headers
- CORS configured for controlled origins
- Cookie parsing with signed cookies

**Static Content**

- Serves static assets:
  - `/public/*` for CSS/JS/images
  - `/src/*` if used by front-end code

---

## 🚀 Getting Started

### Requirements

- Node.js (v14 or higher)
- npm or Yarn
- Environment variables (optional):
  - `PORT` — server port (default: `3000`)
  - `SUPER_SECRET_KEY` — used for signed cookies and JWTs

### Install

```bash
git clone https://github.com/Jj87-huy/Web.git
cd Web
npm install
````

### Run

```bash
node main.js
```

Open a browser and navigate to:

```
http://127.0.0.1:3000/
```

---

## 📌 API Endpoints

### Authentication

| Method | Path                 | Description                      |
| ------ | -------------------- | -------------------------------- |
| POST   | `/api/auth/register` | Register a new user              |
| POST   | `/api/auth/login`    | Log in and receive JWT cookie    |
| POST   | `/api/auth/logout`   | Log out (clears cookie)          |
| GET    | `/api/auth/profile`  | Fetch authenticated user profile |

Requests that modify state require a valid CSRF token delivered via `XSRF-TOKEN` cookie and `X-XSRF-TOKEN` header.

### Static Routes

| Method | Path        | Description              |
| ------ | ----------- | ------------------------ |
| GET    | `/auth`     | Loads `public/auth.html` |
| GET    | `/`         | Loads `public/home.html` |
| GET    | `/public/*` | Static assets            |
| GET    | `/src/*`    | Additional assets        |

---

## 🗂 Data Structure

User accounts are stored under:

```
/data/auth/accounts/{uid}/
```

Each user has:

* `auth.json` — encrypted password hash and metadata
* `profile.json` — public profile information

Indexes:

* `username_index.json` — maps lowercase usernames → user IDs
* `email_index.json` — maps email addresses → user IDs

All updates to indexes use atomic file replacement to avoid corruption.

---

## 🛡 Security Considerations

* CSRF tokens are issued and verified on all mutating HTTP methods.
* JWTs are stored in `HttpOnly` cookies.
* Helmet middleware is used to secure headers.
* Login attempts are rate-limited to prevent brute force.
* Passwords are hashed using bcrypt.

---

## 🧪 Testing

No formal automated tests are included. Manual testing steps:

1. Register a new user via POST `/api/auth/register`
2. Attempt login via POST `/api/auth/login`
3. Access `/api/auth/profile` with valid session cookie

---

## 📜 License

This project is licensed under the **Mozilla Public License 2.0** - see file [LICENSE](LICENSE) for more details.

---

> [!NOTE]
> This repository provides a minimal but complete secure login backend without a database. It is suitable for learning or prototyping, but not recommended for production without replacing filesystem storage with a proper database.