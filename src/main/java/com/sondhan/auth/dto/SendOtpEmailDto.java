package com.sondhan.auth.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
@Builder
@Getter
@Setter
public class SendOtpEmailDto {
    private String mailFrom;
    List<String> mailTo;
    List<String>mailBcc;
    List<String>mailCc;
    private String subject;
    private String body;
    private boolean isHtmlContent;
}
