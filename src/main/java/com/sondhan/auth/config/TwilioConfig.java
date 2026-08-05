/*
package com.sondhan.auth.config;

import com.twilio.Twilio;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

* Initializes the Twilio SDK on startup. Only active when app.twilio.enabled=true.

@Configuration
@ConditionalOnProperty(name = "app.twilio.enabled", havingValue = "true", matchIfMissing = true)
public class TwilioConfig {

  private static final Logger log = LoggerFactory.getLogger(TwilioConfig.class);

  private final String accountSid;
  private final String authToken;

  public TwilioConfig(
      @Value("${app.twilio.account-sid}") String accountSid,
      @Value("${app.twilio.auth-token}") String authToken) {
    this.accountSid = accountSid;
    this.authToken = authToken;
  }

  @PostConstruct
  public void init() {
    Twilio.init(accountSid, authToken);
    log.info("Twilio SDK initialized for account {}", accountSid);
  }
}
*/
