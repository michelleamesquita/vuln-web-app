# Vuln Web App

A deliberately vulnerable web application based on the OWASP Top 10 2021.

## Implemented Vulnerabilities

- **A01:2021 - Broken Access Control**
  - **/people**: Exposes personal data of all users without authorization.
  - **/profile/{user_id}**: Vulnerable to Insecure Direct Object Reference (IDOR). Any user can see any other user's profile by changing the ID.

- **A02:2021 - Cryptographic Failures**
  - **/register**: Stores user passwords in plaintext in the database.
  - **/pythonlogin**: Compares passwords in plaintext.

- **A03:2021 - Injection**
  - **/pythonlogin**: The login form is vulnerable to SQL Injection.
  - **/shell?cmd=...**: The `cmd` parameter is vulnerable to OS Command Injection.
  - **/blog**: The comment form is vulnerable to Stored XSS.
  - **/{script}?script=...**: The URL path is vulnerable to Reflected XSS.

- **A04:2021 - Insecure Design**
  - The application's design lacks proper access control checks from the ground up, as seen in the IDOR vulnerability.

- **A05:2021 - Security Misconfiguration**
  - The application runs with `debug=True` enabled, which can leak sensitive information.
  - Important security headers (like CSP) are disabled.
  - The `SESSION_COOKIE_HTTPONLY` flag is set to `False`.

- **A06:2021 - Vulnerable and Outdated Components**
  - The `app/requirements.txt` file lists dependencies with known public vulnerabilities.

- **A07:2021 - Identification and Authentication Failures**
  - **/pythonlogin**: The login form is vulnerable to User Enumeration, providing different error messages for invalid users vs. invalid passwords. It also lacks protection against brute-force attacks.

- **A08:2021 - Software and Data Integrity Failures**
  - **/uploader**: The file upload feature does not validate file types or names, allowing for potential path traversal or overwriting of critical files.

- **A09:2021 - Security Logging and Monitoring Failures**
  - The application fails to log critical security events, such as failed login attempts.

- **A10:2021 - Server-Side Request Forgery (SSRF)**
  - **/ssrf**: The application fetches URLs provided by the user without validation, allowing requests to internal network resources.

----

## To run
- Install Docker
- To start ```docker-compose up```
- To stop ```docker-compose down```
- To build and change something in code ```docker-compose build```

----
- Web App runs at port 8085

```http://localhost:8085```

- MySQL DB runs at 3306

---
## Routes

- `/`
- `/blog`
- `/form`
- `/home`
- `/people`
- `/profile/{user_id}`
- `/pythonlogin`
- `/pythonlogin/logout`
- `/pythonlogin/upload`
- `/register`
- `/robots.txt`
- `/script`
- `/shell`
- `/sitemap.xml`
- `/ssrf`
- `/uploader`

---

Enjoy it 💜
