package com.sondhan.auth.util;

import java.util.regex.Pattern;

public class MailUtil {
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@"
                    + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$");

    public static boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        return EMAIL_PATTERN
                .matcher(email)
                .matches();
    }

    public static String buildHtmlBody(String recipientName,
                                       String organizationName,
                                       String otp) {

        return """
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verification</title>
                </head>

                <body style="margin:0;padding:0;background:#f4f6f9;font-family:Arial,Helvetica,sans-serif;">

                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0"
                       style="background:#f4f6f9;padding:40px 0;">
                    <tr>
                        <td align="center">

                            <table role="presentation" width="600" cellspacing="0" cellpadding="0"
                                   style="background:#ffffff;border-radius:10px;overflow:hidden;
                                          box-shadow:0 4px 12px rgba(0,0,0,0.08);">

                                <!-- Header -->
                                <tr>
                                    <td align="center"
                                        style="background:#c62828;padding:28px;color:#ffffff;">
                                        <h1 style="margin:0;font-size:28px;">
                                            %s
                                        </h1>

                                        <p style="margin-top:8px;font-size:15px;color:#f5f5f5;">
                                            Account Verification
                                        </p>
                                    </td>
                                </tr>

                                <!-- Content -->
                                <tr>
                                    <td style="padding:40px;">

                                        <p style="margin:0;font-size:18px;color:#333333;">
                                            Hello <strong>%s</strong>,
                                        </p>

                                        <p style="margin-top:20px;font-size:16px;
                                                  line-height:1.7;color:#555555;">
                                            Thank you for registering with
                                            <strong>%s</strong>.
                                        </p>

                                        <p style="font-size:16px;
                                                  line-height:1.7;color:#555555;">
                                            To verify your email address, please use the
                                            following verification code:
                                        </p>

                                        <div style="margin:35px 0;text-align:center;">

                                            <span style="
                                                    display:inline-block;
                                                    background:#f8f8f8;
                                                    border:2px dashed #c62828;
                                                    color:#c62828;
                                                    font-size:34px;
                                                    font-weight:bold;
                                                    letter-spacing:10px;
                                                    padding:18px 40px;
                                                    border-radius:8px;">
                                                %s
                                            </span>

                                        </div>

                                        <p style="font-size:15px;color:#555555;">
                                            This verification code will expire in
                                            <strong>5 minutes</strong>.
                                        </p>

                                        <p style="font-size:15px;color:#555555;">
                                            Never share this code with anyone.
                                            %s will never ask for your verification code.
                                        </p>

                                        <hr style="border:none;border-top:1px solid #eeeeee;margin:35px 0;">

                                        <p style="font-size:14px;color:#777777;line-height:1.6;">
                                            If you did not create an account, you can safely
                                            ignore this email. No further action is required.
                                        </p>

                                    </td>
                                </tr>

                                <!-- Footer -->
                                <tr>
                                    <td align="center"
                                        style="background:#fafafa;
                                               padding:24px;
                                               color:#888888;
                                               font-size:13px;">

                                        <strong>%s</strong><br>

                                        This is an automated email. Please do not reply.

                                    </td>
                                </tr>

                            </table>

                        </td>
                    </tr>
                </table>

                </body>
                </html>
                """.formatted(
                organizationName,
                recipientName,
                organizationName,
                otp,
                organizationName,
                organizationName
        );
    }

    private static String safeNull(String value, String defaultValue) {
        return value == null || value.trim().isEmpty() ? defaultValue : value;
    }

}
