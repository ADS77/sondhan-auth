package com.sondhan.auth.service.notification;

import com.sondhan.auth.domain.User;
import com.sondhan.auth.dto.SendOtpEmailDto;
import com.sondhan.auth.util.MailUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@Slf4j
public class NotificationManagerImpl implements NotificationManager {
    private final EmailService emailService;
    @Value("${app.org.name}")
    private String orgName;
    @Value("${sondhan.email.from}")
    private String orgEmail;

    public NotificationManagerImpl(EmailService emailService) {
        this.emailService = emailService;
    }

    @Override
    public boolean notifyByMail(User user, String email, String otp) {
        SendOtpEmailDto sendOtpEmailDto = SendOtpEmailDto.builder()
                .isHtmlContent(true)
                .subject("Sondhan verification code")
                .mailTo(Collections.singletonList(email))
                .mailFrom(orgEmail)
                .body(MailUtil.buildHtmlBody(user.getFirstName(), orgName, otp))
                .build();
        return emailService.sendOtp(sendOtpEmailDto);
    }
}
