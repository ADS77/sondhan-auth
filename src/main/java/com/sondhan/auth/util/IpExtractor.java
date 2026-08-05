package com.sondhan.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

/**
 * Extracts the real client IP from behind Cloudflare / Kong proxy headers.
 */
public final class IpExtractor {

    private static final String[] CANDIDATE_HEADERS = {
            "CF-Connecting-IP",        // Cloudflare real IP (highest priority)
            "X-Real-IP",               // nginx / Kong
            "X-Forwarded-For",         // standard proxy chain (first entry = client)
    };

    private IpExtractor() {
    }

    /**
     * Returns the best-effort real client IP address.
     * Falls back to {@link HttpServletRequest#getRemoteAddr()} if no proxy header is found.
     */
    public static String extract(HttpServletRequest request) {
        for (String header : CANDIDATE_HEADERS) {
            String value = request.getHeader(header);
            if (StringUtils.hasText(value)) {
                // X-Forwarded-For can be a comma-separated chain; first entry is the client
                return value.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }
}
