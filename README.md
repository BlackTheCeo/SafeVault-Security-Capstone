# SafeVault — Secure Web Application Capstone

## Overview
SafeVault is a secure user management and authentication module built in C# (.NET) and hardened against common web vulnerabilities using Microsoft Copilot.

## 1. Vulnerabilities Identified
- **SQL Injection (SQLi):** Direct string concatenation in database queries allowed malicious payloads (e.g., `' OR '1'='1`) to bypass authentication or manipulate database tables.
- **Cross-Site Scripting (XSS):** Unsanitized user inputs rendered directly in output strings allowed execution of injected `<script>` tags.
- **Weak Credential Storage & Missing Access Controls:** Plaintext password handling and unverified access to administrative routes allowed privilege escalation.

## 2. Security Fixes Applied
- **Input Validation & Parameterized Queries:** Implemented strict allowlist regex validation (`InputSanitizer`) and parameterized `SqlCommand` parameters (`@Username`, `@Email`, `@PasswordHash`, `@Role`) to eliminate SQL injection.
- **XSS Prevention:** Applied `WebUtility.HtmlEncode` on all user-supplied output strings before rendering.
- **Authentication & RBAC:** Implemented salted PBKDF2-SHA256 password hashing (`PasswordHasher`) with constant-time comparison and enforced Role-Based Access Control (`AdminDashboardController`) restricting sensitive routes to `Admin` users.
- **Security Unit Testing:** Added NUnit tests (`SafeVaultSecurityTests.cs`) simulating SQLi payloads, XSS vectors, invalid logins, and unauthorized role access.

## 3. How Microsoft Copilot Assisted
Microsoft Copilot accelerated security auditing by identifying unsafe query patterns, recommending parameterized `SqlCommand` bindings, generating salted PBKDF2 hashing logic, and scaffolding NUnit test cases to verify edge-case attack vectors.
