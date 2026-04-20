# SecureMail API Documentation
### By Swilam - (Securemail team leader)❤️
Base URL: `http://localhost:3000`

All successful responses are wrapped as:
```json
{ "success": true, "message": "Request successful", "data": { ... } }
```
 
All error responses follow:
```json
{ "success": false, "statusCode": 400, "message": "...", "errors": [...], "path": "...", "timestamp": "..." }
```

**Auth:** Send `Authorization: Bearer <access_token>` on all protected routes.

---

## Endpoints Overview

|#| Method | Endpoint | Description | Auth |
|-|--------|----------|-------------|------|
|1| GET | `/health` | Liveness check | ❌ |
|2| POST | `/auth/register` | Register new account | ❌ |
|3| POST | `/auth/verify-register-otp` | Verify registration OTP | ❌ |
|4| POST | `/auth/login` | Login with email & password | ❌ |
|5| POST | `/auth/verify-2fa` | Complete 2FA login | ❌ |
|6| POST | `/auth/logout` | Invalidate current session | 🔒 |
|7| POST | `/auth/forget-password` | Request password reset email | ❌ |
|8| POST | `/auth/reset-password` | Set new password via reset token | ❌ |
|9| GET | `/auth/google/login` | Start Google OAuth | ❌ |
|10| GET | `/auth/google/callback` | Google OAuth callback | ❌ |
|11| GET | `/sessions` | List active sessions | 🔒 |
|12| DELETE | `/sessions` | Revoke all sessions except current | 🔒 |
|13| DELETE | `/sessions/:id` | Revoke specific session | 🔒 |
|14| GET | `/notifications` | Get paginated notifications | 🔒 |
|15| GET | `/notifications/unread-count` | Get unread notifications count | 🔒 |
|16| PATCH | `/notifications/read-all` | Mark all notifications as read | 🔒 |
|17| PATCH | `/notifications/:id/read` | Mark notification as read | 🔒 |
|18| DELETE | `/notifications/:id` | Delete notification | 🔒 |
|19| GET | `/user/profile` | Get current user profile | 🔒 |
|20| GET | `/mailboxes` | List all connected mailboxes | 🔒 |
|21| GET | `/mailboxes/:id` | Get mailbox by ID | 🔒 |
|22| PATCH | `/mailboxes/:id` | Update mailbox settings | 🔒 |
|23| DELETE | `/mailboxes/:id` | Disconnect mailbox | 🔒 |
|24| POST | `/mailboxes/:id/sync` | Trigger manual sync | 🔒 |
|25| GET | `/mailboxes/:id/reports` | Get spam + phishing report | 🔒 |
|26| GET | `/mailboxes/gmail/auth-url` | Get Gmail OAuth2 URL | 🔒 |
|27| POST | `/mailboxes/gmail` | Connect Gmail via OAuth2 | 🔒 |
|28| GET | `/mailboxes/outlook/auth-url` | Get Outlook OAuth2 URL | 🔒 |
|29| POST | `/mailboxes/outlook` | Connect Outlook via OAuth2 | 🔒 |
|30| POST | `/mailboxes/imap` | Connect custom email via IMAP | 🔒 |
|31| GET | `/mailboxes/:mailboxId/inbox` | List inbox emails | 🔒 |
|32| GET | `/mailboxes/:mailboxId/sent` | List sent emails | 🔒 |
|33| GET | `/mailboxes/:mailboxId/spam` | List spam emails | 🔒 |
|34| GET | `/mailboxes/:mailboxId/phishing` | List phishing emails | 🔒 |
|35| GET | `/mailboxes/:mailboxId/emails/:id` | Get full email details | 🔒 |
|36| DELETE | `/mailboxes/:mailboxId/emails/:id` | Delete email | 🔒 |
|37| PATCH | `/mailboxes/:mailboxId/emails/:id/read` | Mark email read/unread | 🔒 |
|38| POST | `/mailboxes/:mailboxId/emails/:id/report` | Report as spam or phishing | 🔒 |
|39| PATCH | `/mailboxes/:mailboxId/emails/:id/reclassify` | Move email to correct folder | 🔒 |
|40| POST | `/mailboxes/:mailboxId/send` | Send new email | 🔒 |
|41| POST | `/mailboxes/:mailboxId/emails/:id/reply` | Reply to email | 🔒 |
|42| POST | `/mailboxes/:mailboxId/emails/:id/forward` | Forward email | 🔒 |
|43| GET | `/analytics/overview` | Overall stats across all mailboxes | 🔒 |
|44| GET | `/analytics/mailboxes/:mailboxId` | Per-mailbox statistics | 🔒 |
|45| GET | `/analytics/activity` | Email activity over time | 🔒 |
|46| GET | `/user-settings` | Get user settings bundle | 🔒 |
|47| PATCH | `/user-settings/profile` | Update profile & avatar | 🔒 |
|48| PATCH | `/user-settings/password` | Change password | 🔒 |
|49| PATCH | `/user-settings/theme` | Set theme mode | 🔒 |
|50| POST | `/user-settings/2fa/setup` | Start 2FA setup | 🔒 |
|51| POST | `/user-settings/2fa/enable` | Enable 2FA | 🔒 |
|52| POST | `/user-settings/2fa/disable` | Disable 2FA | 🔒 |
|53| GET | `/admin/users` | Paginated list of all users | 🔒 |
|54| GET | `/admin/users/:id` | Full user details | 🔒 |
|55| DELETE | `/admin/users/:id` | Soft delete user | 🔒 |
|56| PATCH | `/admin/users/:id/ban` | Ban user | 🔒 |
|57| PATCH | `/admin/users/:id/unban` | Unban user | 🔒 |
|58| GET | `/admin/users/:id/sessions` | View user sessions | 🔒 |
|59| DELETE | `/admin/users/:id/sessions` | Revoke all user sessions | 🔒 |
|60| GET | `/admin/users/:id/mailboxes` | View user mailboxes | 🔒 |
|61| GET | `/admin/users/:id/notifications` | View user notifications | 🔒 |
|62| GET | `/admin/stats/overview` | System-wide overview stats | 🔒 |
|63| GET | `/admin/stats/activity` | Activity over last 30 days | 🔒 |
|64| GET | `/admin/emails` | All emails with filters | 🔒 |
|65| GET | `/admin/emails/:id` | Full email details | 🔒 |
|66| GET | `/admin/emails/phishing` | List phishing emails | 🔒 |
|67| GET | `/admin/emails/spam` | List spam emails | 🔒 |
|68| GET | `/admin/mailboxes` | All mailboxes | 🔒 |
|69| GET | `/admin/mailboxes/:id` | Mailbox details with stats | 🔒 |
|70| DELETE | `/admin/mailboxes/:id` | Force disconnect mailbox | 🔒 |
|71| GET | `/admin/notifications` | All notifications | 🔒 |
|72| POST | `/admin/notifications/broadcast` | Broadcast notification to users | 🔒 |
|73| DELETE | `/admin/notifications/:id` | Delete any notification | 🔒 |
|74| GET | `/admin/audit-logs` | Audit logs with filters | 🔒 |
|75| GET | `/admin/audit-logs/:adminId` | Audit logs for specific admin | 🔒 |
|76| GET | `/admin/dashboard` | Dashboard summary | 🔒 |
|77| POST | `/security-test/analyze` | Run pipeline on custom payload | ❌ |
|78| POST | `/security-test/analyze/phishing` | Run phishing scenario | ❌ |
|79| POST | `/security-test/analyze/bec` | Run BEC scenario | ❌ |
|80| POST | `/security-test/analyze/malware` | Run malware scenario | ❌ |
|81| POST | `/security-test/analyze/spam` | Run spam scenario | ❌ |
|82| POST | `/security-test/analyze/clean` | Run clean email scenario | ❌ |
|83| GET | `/security-test/cache/stats` | Get cache statistics | ❌ |
|84| POST | `/security-test/cache/invalidate` | Invalidate cache entry | ❌ |
|85| POST | `/security-test/intel/url` | Lookup URL reputation | ❌ |
|86| POST | `/security-test/intel/ip` | Lookup IP reputation | ❌ |
|87| POST | `/security-test/intel/domain` | Lookup domain reputation | ❌ |

---

## Table of Contents

- [Health](#health)
- [Auth](#auth)
- [Sessions](#sessions)
- [Notifications](#notifications)
- [User](#user)
- [Mailboxes](#mailboxes)
- [Emails](#emails)
- [Analytics](#analytics)
- [User Settings](#user-settings)
- [Admin - Users](#admin---users)
- [Admin - Stats](#admin---stats)
- [Admin - Emails](#admin---emails)
- [Admin - Mailboxes](#admin---mailboxes)
- [Admin - Notifications](#admin---notifications)
- [Admin - Audit Logs](#admin---audit-logs)
- [Admin - Dashboard](#admin---dashboard)
- [Security Test](#security-test)

---

## Health

### `GET /health`
Liveness check.

**Response `200`:**
```json
{ "success": true, "message": "Request successful", "data": "SecureMail API" }
```

---

## Auth

### `POST /auth/register`
Register a new local account. Sends OTP to email.

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | ✅ | Valid email address |
| password | string | ✅ | 8-32 chars, uppercase + lowercase + number |
| confirmPassword | string | ✅ | Must match password |
| username | string | ✅ | 3-20 characters |

**Response `201`:**
```json
{ "data": { "message": "OTP sent to your email" } }
```

---

### `POST /auth/verify-register-otp`
Verify the OTP sent during registration.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| email | string | ✅ |
| otp | string | ✅ | 6-digit OTP |

**Response `200`:**
```json
{ "data": { "message": "Account verified successfully" } }
```

---

### `POST /auth/login`
Login with email and password.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| email | string | ✅ |
| password | string | ✅ |

**Response `200` (no 2FA):**
```json
{ "data": { "token": "eyJhbGci..." } }
```

**Response `200` (2FA enabled):**
```json
{ "data": { "requires2FA": true, "tempToken": "eyJhbGci..." } }
```

---

### `POST /auth/verify-2fa`
Complete login after 2FA. Send `Authorization: Bearer <tempToken>`.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| code | string | ✅ | 6-digit TOTP |

**Response `200`:**
```json
{ "data": { "token": "eyJhbGci..." } }
```

---

### `POST /auth/logout` 🔒
Invalidate current session/token.

**Response `200`:**
```json
{ "data": { "message": "Logout successfully" } }
```

---

### `POST /auth/forget-password`
Request a password reset email.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| email | string | ✅ |

**Response `200`:**
```json
{ "data": { "message": "If email exists, reset link will be sent" } }
```

---

### `POST /auth/reset-password`
Set a new password using the reset token.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| resetPasswordToken | string | ✅ |
| newPassword | string | ✅ | 8-32 chars |

**Response `200`:**
```json
{ "data": { "message": "Password updated successfully" } }
```

---

### `GET /auth/google/login`
Redirect to Google OAuth. Browser only, not for mobile/API.

---

### `GET /auth/google/callback`
Google OAuth callback. Redirects to frontend with token query param.

---

## Sessions

### `GET /sessions` 🔒
List all active sessions for the current user.

**Response `200`:**
```json
[
  {
    "id": 1,
    "ipAddress": "192.168.1.1",
    "deviceOs": "Windows",
    "deviceBrowser": "Chrome",
    "userAgent": "...",
    "loginAt": "2026-04-11T12:00:00.000Z",
    "expiresAt": "2026-04-18T12:00:00.000Z",
    "isCurrent": true
  }
]
```

---

### `DELETE /sessions` 🔒
Revoke all sessions except the current one.

---

### `DELETE /sessions/:id` 🔒
Revoke a specific session.

**Path Params:** `id` (number) - Session ID

---

## Notifications

### `GET /notifications` 🔒
Get paginated list of notifications.

**Query Params:**
| Param | Type | Default |
|-------|------|---------|
| page | number | 1 |
| limit | number | 20 (max 100) |

---

### `GET /notifications/unread-count` 🔒
Get count of unread notifications.

---

### `PATCH /notifications/read-all` 🔒
Mark all notifications as read.

---

### `PATCH /notifications/:id/read` 🔒
Mark a specific notification as read.

**Path Params:** `id` (number) - Notification ID

---

### `DELETE /notifications/:id` 🔒
Delete a notification.

**Path Params:** `id` (number) - Notification ID

---

## User

### `GET /user/profile` 🔒
Get the current user's profile.

**Response `200`:**
```json
{
  "data": {
    "id": 1,
    "email": "user@example.com",
    "username": "john_doe",
    "avatar": "https://cdn.example/avatar.png",
    "isVerified": true
  }
}
```

---

## Mailboxes

### `GET /mailboxes` 🔒
List all connected mailboxes.

---

### `GET /mailboxes/:id` 🔒
Get mailbox by ID.

---

### `PATCH /mailboxes/:id` 🔒
Update mailbox settings.

**Request Body:**
| Field | Type | Description |
|-------|------|-------------|
| displayName | string | Display name for the mailbox |
| pushNotificationsEnabled | boolean | Enable push notifications |

---

### `DELETE /mailboxes/:id` 🔒
Disconnect a mailbox.

---

### `POST /mailboxes/:id/sync` 🔒
Trigger a manual sync for a mailbox.

---

### `GET /mailboxes/:id/reports` 🔒
Get flagged emails report (spam + phishing) for a mailbox.

---

### `GET /mailboxes/gmail/auth-url` 🔒
Get Gmail OAuth2 authorization URL.

**Query Params:** `redirectUri` (required)

---

### `POST /mailboxes/gmail` 🔒
Connect Gmail via OAuth2.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| code | string | ✅ | OAuth2 authorization code |
| redirectUri | string | ✅ | Must match Google Console |

---

### `GET /mailboxes/outlook/auth-url` 🔒
Get Outlook OAuth2 authorization URL.

**Query Params:** `redirectUri` (required)

---

### `POST /mailboxes/outlook` 🔒
Connect Outlook via OAuth2.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| code | string | ✅ |
| redirectUri | string | ✅ | Must match Azure App registration |

---

### `POST /mailboxes/imap` 🔒
Connect a custom email via IMAP.

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| host | string | ✅ | IMAP server host |
| port | number | ✅ | 1-65535 (993 for SSL) |
| email | string | ✅ | Email for authentication |
| password | string | ✅ | Password or app password |
| secure | boolean | ✅ | Use SSL/TLS (default: true) |
| displayName | string | ✅ | Display name for the mailbox |
| smtpHost | string | ❌ | SMTP host for sending |
| smtpPort | number | ❌ | 587 for TLS, 465 for SSL |

---

## Emails

### `GET /mailboxes/:mailboxId/inbox` 🔒
List inbox emails (paginated).

**Query Params:**
| Param | Default | Max |
|-------|---------|-----|
| page | 1 | - |
| limit | 20 | 100 |

---

### `GET /mailboxes/:mailboxId/sent` 🔒
List sent emails (paginated).

---

### `GET /mailboxes/:mailboxId/spam` 🔒
List spam emails (paginated).

---

### `GET /mailboxes/:mailboxId/phishing` 🔒
List phishing emails (paginated).

---

### `GET /mailboxes/:mailboxId/emails/:id` 🔒
Get full email details including body, attachments, security verdict, and AI report.

---

### `DELETE /mailboxes/:mailboxId/emails/:id` 🔒
Delete email. Moves to TRASH first; permanently deletes if already in TRASH.

---

### `PATCH /mailboxes/:mailboxId/emails/:id/read` 🔒
Mark email as read or unread.

**Request Body:**
```json
{ "read": true }
```

---

### `POST /mailboxes/:mailboxId/emails/:id/report` 🔒
Report an email as spam or phishing.

**Request Body:**
```json
{ "type": "spam" }
```
Type options: `spam` | `phishing`

---

### `PATCH /mailboxes/:mailboxId/emails/:id/reclassify` 🔒
Override email classification and move to correct folder.

**Request Body:**
```json
{ "folder": "inbox" }
```
Folder options: `inbox` | `sent` | `spam` | `phishing` | `trash`

---

### `POST /mailboxes/:mailboxId/send` 🔒
Send a new email. Accepts `multipart/form-data`. Max 10 attachments, 10MB each.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| to | string (email) | ✅ | Recipient |
| subject | string | ✅ | Email subject |
| cc | string | ❌ | Comma-separated CC |
| bcc | string | ❌ | Comma-separated BCC |
| bodyText | string | ❌ | Plain text body |
| bodyHtml | string | ❌ | HTML body (overrides bodyText) |
| attachments | file[] | ❌ | Up to 10 files |

**Response `202`:** Email queued for sending.

---

### `POST /mailboxes/:mailboxId/emails/:id/reply` 🔒
Reply to an email. Accepts `multipart/form-data`.

**Form Fields:**
| Field | Type | Required |
|-------|------|----------|
| content | string | ✅ |
| bodyHtml | string | ❌ |
| attachments | file[] | ❌ |

**Response `202`:** Reply queued.

---

### `POST /mailboxes/:mailboxId/emails/:id/forward` 🔒
Forward an email to a new recipient. Accepts `multipart/form-data`.

**Form Fields:**
| Field | Type | Required |
|-------|------|----------|
| to | string (email) | ✅ |
| message | string | ❌ | Prepended message |
| attachments | file[] | ❌ |

**Response `202`:** Forward queued.

---

## Analytics

### `GET /analytics/overview` 🔒
Get overall stats across all mailboxes.

---

### `GET /analytics/mailboxes/:mailboxId` 🔒
Get per-mailbox statistics.

---

### `GET /analytics/activity` 🔒
Get email activity over time.

**Query Params:**
| Param | Options |
|-------|---------|
| period | `daily` \| `weekly` \| `monthly` |

---

## User Settings

### `GET /user-settings` 🔒
Get user settings bundle.

**Response `200`:**
```json
{ "data": { "themeMode": "system", "notifications": true } }
```

---

### `PATCH /user-settings/profile` 🔒
Update profile. Accepts `multipart/form-data`.

**Form Fields:**
| Field | Type | Description |
|-------|------|-------------|
| username | string | New username |
| avatar | file | JPEG/PNG/GIF/WebP, max 5MB |

---

### `PATCH /user-settings/password` 🔒
Change password.

**Request Body:**
| Field | Type | Required |
|-------|------|----------|
| currentPassword | string | ✅ |
| newPassword | string | ✅ | 8-32 chars |

---

### `PATCH /user-settings/theme` 🔒
Set theme mode.

**Request Body:**
```json
{ "themeMode": "DARK" }
```
Options: `LIGHT` | `DARK`

---

### `POST /user-settings/2fa/setup` 🔒
Start 2FA setup. Returns secret and OTP auth URL for QR code.

**Response `200`:**
```json
{ "data": { "secret": "BASE32...", "otpauthUrl": "otpauth://..." } }
```

---

### `POST /user-settings/2fa/enable` 🔒
Enable 2FA with TOTP code.

**Request Body:**
```json
{ "code": "123456" }
```

---

### `POST /user-settings/2fa/disable` 🔒
Disable 2FA with TOTP code.

**Request Body:**
```json
{ "code": "123456" }
```

---

## Admin - Users

> All admin routes require admin role JWT.

### `GET /admin/users` 🔒
Paginated list of all users.

**Query Params:**
| Param | Type | Description |
|-------|------|-------------|
| page | number | Default: 1 |
| limit | number | Default: 20, max: 100 |
| search | string | Search by name or email |
| active | boolean | Filter by active users |
| banned | boolean | Filter by banned users |

---

### `GET /admin/users/:id` 🔒
Full user details.

---

### `DELETE /admin/users/:id` 🔒
Soft delete a user.

---

### `PATCH /admin/users/:id/ban` 🔒
Ban a user.

---

### `PATCH /admin/users/:id/unban` 🔒
Unban a user.

---

### `GET /admin/users/:id/sessions` 🔒
View all sessions for a user.

---

### `DELETE /admin/users/:id/sessions` 🔒
Revoke all sessions for a user.

---

### `GET /admin/users/:id/mailboxes` 🔒
View all mailboxes for a user.

---

### `GET /admin/users/:id/notifications` 🔒
View notifications for a user (paginated).

---

## Admin - Stats

### `GET /admin/stats/overview` 🔒
System-wide overview statistics.

---

### `GET /admin/stats/activity` 🔒
Activity over the last 30 days.

---

## Admin - Emails

### `GET /admin/emails` 🔒
Paginated list of all emails with filters.

**Query Params:**
| Param | Type | Description |
|-------|------|-------------|
| page | number | Default: 1 |
| limit | number | Max: 100 |
| classification | string | `inbox` \| `spam` \| `phishing` |
| fromDate | string | ISO date filter |
| toDate | string | ISO date filter |
| mailboxId | number | Filter by mailbox |
| search | string | Search by subject or sender |

---

### `GET /admin/emails/:id` 🔒
Full email details.

---

### `GET /admin/emails/phishing` 🔒
Paginated list of phishing emails.

---

### `GET /admin/emails/spam` 🔒
Paginated list of spam emails.

---

## Admin - Mailboxes

### `GET /admin/mailboxes` 🔒
Paginated list of all mailboxes.

---

### `GET /admin/mailboxes/:id` 🔒
Mailbox details with stats.

---

### `DELETE /admin/mailboxes/:id` 🔒
Force disconnect a mailbox.

---

## Admin - Notifications

### `GET /admin/notifications` 🔒
Paginated list of all notifications.

---

### `POST /admin/notifications/broadcast` 🔒
Broadcast a notification to users.

**Request Body:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | ✅ | |
| message | string | ✅ | |
| type | string | ✅ | See options below |
| userIds | string[] | ❌ | Empty = broadcast to all |

**Type options:**
`NEW_LOGIN_DETECTED` | `LOW_MAILBOX_SPACE` | `PASSWORD_CHANGED` | `WEEKLY_SECURITY_REPORT` | `NEW_EMAIL_RECEIVED` | `PHISHING_DETECTED` | `MALWARE_DETECTED`

---

### `DELETE /admin/notifications/:id` 🔒
Delete any notification.

---

## Admin - Audit Logs

### `GET /admin/audit-logs` 🔒
Paginated audit logs with filters.

**Query Params:**
| Param | Type | Description |
|-------|------|-------------|
| page | number | Default: 1 |
| limit | number | Max: 100 |
| action | string | Filter by action |
| targetType | string | `USER` \| `MAILBOX` \| `EMAIL` \| `NOTIFICATION` |
| fromDate | string | ISO date |
| toDate | string | ISO date |

---

### `GET /admin/audit-logs/:adminId` 🔒
Audit logs for a specific admin (same query params as above).

---

## Admin - Dashboard

### `GET /admin/dashboard` 🔒
Dashboard summary.

---

## Security Test

> Dev/test only. Disabled in production.

### `POST /security-test/analyze`
Run the security pipeline on a custom payload.

**Request Body:**
| Field | Type | Description |
|-------|------|-------------|
| fromAddr | string | Sender email |
| fromName | string | Sender name |
| toAddr | string | Recipient |
| subject | string | Email subject |
| bodyText | string | Plain text body |
| bodyHtml | string | HTML body |
| headers | object | Email headers |
| mailBoxId | number | |
| userId | number | |
| attachments | array | `[{ filename, mimeType, size, storagePath }]` |

---

### `POST /security-test/analyze/phishing`
Run the built-in phishing scenario.

---

### `POST /security-test/analyze/bec`
Run the built-in BEC (Business Email Compromise) scenario.

---

### `POST /security-test/analyze/malware`
Run the built-in malware scenario.

---

### `POST /security-test/analyze/spam`
Run the built-in spam scenario.

---

### `POST /security-test/analyze/clean`
Run the built-in clean email scenario.

---

### `GET /security-test/cache/stats`
Get intelligence cache statistics.

---

### `POST /security-test/cache/invalidate`
Invalidate an intel cache entry.

**Request Body:**
```json
{ "type": "url", "value": "https://evil.test/phish" }
```
Type options: `url` | `ip` | `domain`

---

### `POST /security-test/intel/url`
Lookup URL reputation.

**Request Body:**
```json
{ "url": "https://example.com/path" }
```

---

### `POST /security-test/intel/ip`
Lookup IP reputation.

**Request Body:**
```json
{ "ip": "8.8.8.8" }
```

---

### `POST /security-test/intel/domain`
Lookup domain reputation.

**Request Body:**
```json
{ "domain": "example.com" }
```

---

## Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (queued) |
| 302 | Redirect |
| 400 | Validation error / bad request |
| 401 | Missing or invalid JWT |
| 403 | Authenticated but not authorized |
| 404 | Resource not found |
| 409 | Conflict (e.g. duplicate) |
| 429 | Rate limit exceeded |
| 500 | Unexpected server error |
| 503 | Dependency unavailable (e.g. database) |

---

> 🔒 = Requires `Authorization: Bearer <token>` header