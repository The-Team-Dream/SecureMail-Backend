# SecureMail Backend API Documentation

This document provides a comprehensive overview of the SecureMail Backend API.

## Authentication & Base URL
- **Base URL**: `http://localhost:3000` (Development)
- **Format**: JSON
- **Auth Strategy**: JWT Bearer Token

Most endpoints require an `Authorization` header:
`Authorization: Bearer <JWT_TOKEN>`

---

## 1. Authentication (`/auth`)

Endpoints for account management, login, and security verification.

### POST `/auth/register`
- **Description**: Register a new local account. Sends a 6-digit OTP to the email.
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "username": "john_doe",
    "password": "Password123!"
  }
  ```
- **Response (201)**:
  ```json
  {
    "success": true,
    "message": "Request successful",
    "data": { "message": "OTP sent to your email" }
  }
  ```

### POST `/auth/verify-register-otp`
- **Description**: Verify the 6-digit OTP received after registration.
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "otp": "123456"
  }
  ```
- **Response (200)**:
  ```json
  {
    "success": true,
    "message": "Request successful",
    "data": { "message": "Account verified successfully" }
  }
  ```

### POST `/auth/resend-otp`
- **Description**: Resend the registration OTP. Rate-limited to once per 60 seconds.
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "email": "user@example.com"
  }
  ```
- **Response (200)**:
  ```json
  {
    "success": true,
    "message": "Request successful",
    "data": { "message": "If your account is pending verification, a new OTP has been sent." }
  }
  ```

### POST `/auth/login`
- **Description**: Authenticate with email and password.
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "Password123!"
  }
  ```
- **Response (200)**:
  - If 2FA is **Disabled**:
    ```json
    {
      "success": true,
      "message": "Request successful",
      "data": { "token": "JWT_STRING" }
    }
    ```
  - If 2FA is **Enabled**:
    ```json
    {
      "success": true,
      "message": "Request successful",
      "data": { "requires2FA": true, "tempToken": "TEMP_JWT" }
    }
    ```

### POST `/auth/verify-2fa`
- **Description**: Complete login using TOTP code.
- **Auth Required**: No (Requires `Authorization: Bearer <tempToken>` header)
- **Request Body**:
  ```json
  {
    "code": "123456"
  }
  ```
- **Response (200)**:
  ```json
  {
    "success": true,
    "message": "Request successful",
    "data": { "token": "JWT_STRING" }
  }
  ```

### POST `/auth/logout`
- **Description**: Blacklist the current JWT and revoke the session.
- **Auth Required**: Yes
- **Response (200)**:
  ```json
  {
    "success": true,
    "message": "Request successful",
    "data": { "message": "Logout successfully" }
  }
  ```

### POST `/auth/forget-password`
- **Description**: Request a password reset link. Returns generic response to prevent email enumeration.
- **Auth Required**: No
- **Request Body**: `{ "email": "user@example.com" }`
- **Response (200)**: `{ "message": "If email exists, reset link will be sent" }`

### POST `/auth/reset-password`
- **Description**: Reset password using token from email.
- **Auth Required**: No
- **Request Body**:
  ```json
  {
    "resetPasswordToken": "TOKEN",
    "newPassword": "NewPassword123!"
  }
  ```

---

## 2. User & Settings (`/user`, `/user-settings`)

### GET `/user/profile`
- **Description**: Get current user's profile information.
- **Auth Required**: Yes

### GET `/user-settings`
- **Description**: Get all user settings (theme, notifications, etc.).
- **Auth Required**: Yes

### PATCH `/user-settings/profile`
- **Description**: Update username and/or avatar.
- **Format**: `multipart/form-data`
- **Fields**: `username` (string), `avatar` (file)

### PATCH `/user-settings/notifications`
- **Description**: Toggle push notification preference.
- **Auth Required**: Yes
- **Request Body**: `{ "notificationsEnabled": true }`

### POST `/user-settings/2fa/setup`
- **Description**: Start 2FA setup. Returns secret and QR code.
- **Auth Required**: Yes

---

## 3. Mailboxes (`/mailboxes`)

### GET `/mailboxes`
- **Description**: List all connected mailboxes.
- **Auth Required**: Yes

### POST `/mailboxes/imap`
- **Description**: Connect a custom email via IMAP/SMTP.
- **Auth Required**: Yes
- **Request Body**:
  ```json
  {
    "email": "work@company.com",
    "password": "Password",
    "imapHost": "imap.company.com",
    "imapPort": 993,
    "smtpHost": "smtp.company.com",
    "smtpPort": 465
  }
  ```

### POST `/mailboxes/:id/sync`
- **Description**: Trigger manual background sync for a mailbox.
- **Auth Required**: Yes

---

## 4. Emails (`/mailboxes/:mailboxId/...`)

### GET `/mailboxes/:id/inbox`
- **Description**: Paginated list of inbox emails.
- **Query Params**: `page`, `limit`

### GET `/mailboxes/:id/emails/search`
- **Description**: Search emails by keyword in subject, from address, or from name.
- **Query Params**: `q`, `page`, `limit`

### GET `/mailboxes/:id/starred`
- **Description**: List starred/flagged emails.

### GET `/mailboxes/:id/malware`
- **Description**: List quarantined malware emails.

### GET `/mailboxes/:id/trash`
- **Description**: List deleted emails.

### GET `/mailboxes/:id/emails/:id/attachments/:attachmentId/download`
- **Description**: Download or redirect to an email attachment.
- **Response**: File stream or 302 Redirect.

### POST `/mailboxes/:id/send`
- **Description**: Send a new email.
- **Format**: `multipart/form-data`
- **Fields**: `to`, `cc`, `bcc`, `subject`, `bodyText`, `bodyHtml`, `attachments` (multiple files)

---

## 5. Analytics (`/analytics`)

### GET `/analytics/overview`
- **Description**: Aggregated security stats across all mailboxes.

### GET `/analytics/activity`
- **Description**: Threat activity over time.
- **Query Params**: `period` (daily, weekly, monthly)

---

## 6. Notifications (`/notifications`)

### GET `/notifications`
- **Description**: List recent security events and system notifications.

### PATCH `/notifications/read-all`
- **Description**: Mark all as read.

---

## 7. Admin (`/admin`)
*Accessible only to users with `ADMIN` role.*

### GET `/admin/dashboard`
- **Description**: Global system health and metrics.

### GET `/admin/users`
- **Description**: Manage users (search, ban, delete).

### POST `/admin/notifications/broadcast`
- **Description**: Send notification to specific users or everyone.

---

## Recent Updates

### Endpoints Added
- `POST /auth/resend-otp`: Added rate-limited OTP resend capability.
- `GET /mailboxes/:id/starred`: Dedicated folder for flagged emails.
- `GET /mailboxes/:id/malware`: Quarantined malware view.
- `GET /mailboxes/:id/trash`: Deleted emails view.
- `GET /mailboxes/:id/emails/search`: Multi-field keyword search.
- `GET /mailboxes/:id/emails/:id/attachments/:attachmentId/download`: Unified attachment delivery.
- `PATCH /user-settings/notifications`: User-controlled notification toggle.

### Security Improvements
- **Token Encryption**: OAuth tokens for Google/Outlook are now encrypted at rest using AES-256-GCM.
- **Enumeration Protection**: Forget password and OTP resend endpoints now use generic responses to prevent user discovery.
- **Concurrency Gating**: Background sync workers now have a concurrency limit (5) to prevent resource exhaustion.
- **Admin Hardening**: Security test endpoints are fully disabled in production and strictly role-gated in dev.

---

## Inconsistencies Found
- **Prisma Schema**: `User` model still contains legacy `oauthAccessToken` and `oauthRefreshToken` columns for backwards compatibility, though they are now unused in favor of the encrypted versions.
- **Attachment Storage**: Transitioning from local storage to Cloudinary; some older emails may still point to local paths until re-synced.
