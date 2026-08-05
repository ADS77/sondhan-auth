package com.sondhan.auth.service.notification;

import com.sondhan.auth.dto.SendOtpEmailDto;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    public EmailServiceImpl(JavaMailSender javaMailSender) {
        this.mailSender = javaMailSender;
    }

    @Override
    public boolean sendOtp(SendOtpEmailDto sendOtpEmailDto) {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true);
            helper.setFrom(new InternetAddress(sendOtpEmailDto.getMailFrom()));
            helper.setTo(sendOtpEmailDto.getMailTo().toArray(new String[0]));

            if (sendOtpEmailDto.getMailCc() != null && !sendOtpEmailDto.getMailCc().isEmpty()) {
                helper.setCc(sendOtpEmailDto.getMailCc().toArray(new String[0]));
            }
            if (sendOtpEmailDto.getMailBcc() != null && !sendOtpEmailDto.getMailBcc().isEmpty()) {
                helper.setBcc(sendOtpEmailDto.getMailBcc().toArray(new String[0]));
            }

            helper.setSubject(sendOtpEmailDto.getSubject());
            helper.setText(sendOtpEmailDto.getBody(), sendOtpEmailDto.isHtmlContent());

       /*     if (sendOtpEmailDto.getAttachments() != null && !mailRequest.getAttachments().isEmpty()) {
                for (MailAttachment attachment : mailRequest.getAttachments()) {
                    helper.addAttachment(attachment.getAttachmentName(), (DataSource) attachment.getDataSource());
                }
            }
            if (mailRequest.getInlineImages() != null && !mailRequest.getInlineImages().isEmpty()) {
                for (Map.Entry<String, MailAttachment> entry : mailRequest.getInlineImages().entrySet()) {
                    helper.addInline(entry.getKey(), (DataSource) entry.getValue().getDataSource());
                }
            }*/

            mailSender.send(mimeMessage);
            log.info("Email sent successfully...");
            return true;
        } catch (MessagingException e) {
            log.error("Error sending email to: {}, {}", sendOtpEmailDto.getMailTo(), e.getCause());
            e.printStackTrace();
            return false;
        }
    }
}
