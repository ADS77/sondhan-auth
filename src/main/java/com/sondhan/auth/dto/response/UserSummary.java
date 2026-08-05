package com.sondhan.auth.dto.response;

import java.util.List;
import java.util.UUID;

public record UserSummary(
        UUID id,
        List<String> roles) {
}
