export const otpTemplate = (name: string, otp: string) => `<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <title>Welcome</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #f4f7f1;
            font-family: Arial, Helvetica, sans-serif;
        }

        .container {
            max-width: 600px;
            margin: 30px auto;
            background-color: #ffffff;
            border-radius: 12px;
            border: solid #95BB63;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.06);
        }

        .header {
            background: #95BB63;
            padding: 24px;
            text-align: center;
            color: #ffffff;
        }

        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: bold;
        }

        .content {
            background-color: #ffffff;
            padding: 32px 24px;
            color: #2e2e2e;
            line-height: 1.6;
            text-align: center;
        }

        .content h2 {
            margin-top: 0;
            color: #95BB63;
        }

        .button {
            display: inline-block;
            margin-top: 24px;
            padding: 14px 32px;
            background-color: #95bb63;
            color: #ffffff;
            text-decoration: none;
            border-radius: 999px;
            font-weight: bold;
            font-size: 14px;
        }

        .footer {
            background-color: #95bb6350;
            padding: 16px;
            text-align: center;
            font-size: 12px;
            color: #6f7a65;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="header">
            <h1>Secure Mail Verification</h1>
        </div>

        <div class="content">
            <h2>Hi ${name} 👋</h2>
            <p>
                Use the verification code below to complete your sign in.
                This code is valid for a short time only.
            </p>

            <h1 style="letter-spacing: 6px; margin: 24px 0;">
                ${otp}
            </h1>

            <p>
                If you didn’t request this code, you can safely ignore this email.
            </p>
        </div>

        <div class="footer">
            Need help? Just reply to this email — we’ve got you.
        </div>
    </div>
</body>

</html>
`;
