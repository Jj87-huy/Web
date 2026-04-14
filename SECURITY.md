# Security Policy

## Supported Versions

This project is under active development. Only the latest version on the `main` branch is supported with security updates.

| Version | Supported |
|---------|-----------|
| main    | ✅ Yes     |
| older   | ❌ No      |

---

## Reporting a Vulnerability

If you discover a security vulnerability, **do not open a public issue**.

Instead, please report it privately by emailing:

> haoallain964@gmail.com

Include the following details:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Any suggested mitigation (if known)

You will receive an acknowledgment within **48 hours**.

---

## Security Design Overview

This project implements several security mechanisms:

- Authentication using JSON Web Tokens stored in HttpOnly cookies
- CSRF protection using double-submit token pattern
- Password hashing with bcrypt
- Helmet for secure HTTP headers
- Input validation for username, email, and password
- Atomic file operations to prevent data corruption
- Basic protection against brute-force login attempts

---

## Scope

This security policy applies to:

- Authentication system (`/api/auth/*`)
- File-based user storage under `/data/auth`
- Middleware related to sessions, cookies, and CSRF

It does **not** cover:

- Third-party dependencies vulnerabilities (handled by npm advisories)
- Misconfiguration in deployment environments

---

## Disclosure Policy

After a vulnerability is reported:

1. The issue will be investigated and confirmed.
2. A fix will be developed and tested.
3. The fix will be released.
4. Public disclosure will occur after the fix is available.

We appreciate responsible disclosure and will credit reporters when appropriate.

---

## Best Practices for Deployment

If you deploy this project:

- Always set a strong `SUPER_SECRET_KEY`
- Use HTTPS in production
- Do not expose the `/data` directory publicly
- Run the server behind a reverse proxy (e.g., Nginx)
- Regularly update dependencies with `npm audit fix`

---

## Acknowledgements

We thank the security community for helping keep this project safe.