package com.iam.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.io.IOException;
import java.time.Duration;

public class RedisRateLimitingFilter implements Filter {
    private final StringRedisTemplate redisTemplate;
    //TODO: this needs to be configurable
    private static int MAX_REQUESTS_PER_SECOND = 10;
    private static final String RATE_LIMIT_PREFIX = "rate_limit:";

    public RedisRateLimitingFilter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String path = httpRequest.getRequestURI();
        if(path.startsWith("/auth/login") || path.startsWith("/oauth2/token")){
            String clientIp = getClientIp(httpRequest);
            String redisKey = RATE_LIMIT_PREFIX + clientIp;

            if(isRateLimited(redisKey)){
                httpResponse.setStatus(429); // Too Many Requests
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write("{\"success\":false,\"message\":\"Rate limit exceeded. Please try again later.\",\"errorCode\":\"RATE_LIMIT_EXCEEDED\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean isRateLimited(String redisKey) {
        Long currentCount = redisTemplate.opsForValue().increment(redisKey);

        if (currentCount != null && currentCount == 1L) {
            // Set expiration window to 60 seconds on the first request
            redisTemplate.expire(redisKey, Duration.ofSeconds(1));
        }

        return currentCount != null && currentCount > MAX_REQUESTS_PER_SECOND;
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
