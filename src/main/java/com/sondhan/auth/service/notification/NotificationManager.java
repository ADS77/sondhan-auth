package com.sondhan.auth.service.notification;

import com.sondhan.auth.domain.User;

public interface NotificationManager {
    public boolean notifyByMail(User user, String email, String otp);
}
