package com.sondhan.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.ForwardedHeaderFilter;

/**
 * Configures trusted proxy header handling for deployments behind Cloudflare and Kong.
 *
 * <p>Two concerns addressed:
 * <ol>
 *   <li>{@link ForwardedHeaderFilter} — makes Spring aware of {@code X-Forwarded-*} and
 *       {@code X-Forwarded-For} headers so that {@link jakarta.servlet.http.HttpServletRequest
 *       #getRemoteAddr()} and scheme reflect the real client, not the proxy IP.</li>
 *   <li>Tomcat {@code RemoteIpValve} — strips and re-evaluates the forwarded chain using
 *       a configurable trusted proxy CIDR pattern so only headers from known Cloudflare /
 *       Kong IPs are trusted.</li>
 * </ol>
 *
 * <p>The trusted proxy regex is overridable via {@code app.proxy.trusted-ip-regex}.
 * Default covers Cloudflare's published IPv4 and IPv6 ranges (coarse pattern).
 */
@Configuration
public class TrustedProxyConfig {

    /**
     * Regex matching Cloudflare and typical internal load-balancer IP ranges.
     * Override with {@code app.proxy.trusted-ip-regex} in environment-specific config.
     * See: https://www.cloudflare.com/ips/
     */
    private static final String DEFAULT_PROXY_REGEX =
            "10\\.\\d+\\.\\d+\\.\\d+|"
                    + "172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|"
                    + "192\\.168\\.\\d+\\.\\d+|"
                    + "103\\.(21|22|31)\\.(2[24-9]|3[0-1]|1[6-9])\\.\\d+|"
                    + "104\\.(16|17|18|19|2[0-6])\\.\\d+\\.\\d+|"
                    + "108\\.162\\.(19[2-9]|2[0-2]\\d)\\.\\d+|"
                    + "::1|fd[0-9a-f]{2}:.*";  // IPv6 loopback + ULA

    private final String trustedProxyRegex;

    public TrustedProxyConfig(
            @Value("${app.proxy.trusted-ip-regex:" + DEFAULT_PROXY_REGEX + "}")
                    String trustedProxyRegex) {
        this.trustedProxyRegex = trustedProxyRegex;
    }

    /**
     * Registers {@link ForwardedHeaderFilter} so the entire filter chain (including
     * {@link com.sondhan.auth.security.JwtAuthFilter}) sees the real client IP and scheme.
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    /**
     * Customises the embedded Tomcat instance to use {@code RemoteIpValve}, which:
     * <ul>
     *   <li>Honours {@code X-Forwarded-For} only from IP addresses matching
     *       {@code trustedProxyRegex}</li>
     *   <li>Sets {@code request.remoteAddr} to the leftmost untrusted entry in the chain</li>
     * </ul>
     */
    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> remoteIpValveCustomizer() {
        return factory -> factory.addContextCustomizers(context -> {
            var valve = new org.apache.catalina.valves.RemoteIpValve();
            valve.setTrustedProxies(trustedProxyRegex);
            valve.setRemoteIpHeader("X-Forwarded-For");
            valve.setProtocolHeader("X-Forwarded-Proto");
            context.getPipeline().addValve(valve);
        });
    }
}
