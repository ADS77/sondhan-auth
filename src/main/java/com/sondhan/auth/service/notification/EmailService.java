package com.sondhan.auth.service.notification;

import com.sondhan.auth.dto.SendOtpEmailDto;

public interface EmailService {

    public boolean sendOtp(SendOtpEmailDto sendOtpEmailDto);
}
