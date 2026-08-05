package com.sondhan.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Phone number is required")
        @Pattern(regexp = "^\\+[1-9]\\d{7,14}$", message = "Phone must be in E.164 format")
        String phone,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email address")
        @Size(max = 254, message = "Email must not exceed 254 characters")
        String email,

        @NotBlank(message = "First name is required")
        @Size(max = 100)
        @JsonProperty("first_name")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(max = 100)
        @JsonProperty("last_name")
        String lastName,

        @NotBlank(message = "Blood group is required")
        @Pattern(regexp = "^(A|B|AB|O)[+-]$", message = "Invalid blood group")
        @JsonProperty("blood_group")
        String bloodGroup) {}

