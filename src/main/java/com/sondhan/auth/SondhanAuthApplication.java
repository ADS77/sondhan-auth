package com.sondhan.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableAsync;

/** Sondhan Auth Service — entry point. */
@SpringBootApplication
@EnableAsync
@ConfigurationPropertiesScan
public class SondhanAuthApplication {

  public static void main(String[] args) {
    SpringApplication.run(SondhanAuthApplication.class, args);
  }
}
