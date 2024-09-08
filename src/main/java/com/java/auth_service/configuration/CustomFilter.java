package com.java.auth_service.configuration;

import com.java.auth_service.service.JwtTokenProvider;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomFilter implements Filter {

    private final JwtTokenProvider jwtTokenProvider;

    private final String[] PUBLIC_ENDPOINTS = {
            "/users", "/auth/login", "/auth/introspect", "/auth/logout", "/auth/refresh"
    };

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        log.info("Start filter");
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String url = request.getRequestURI();
        if(url.contains("/login")){
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        final String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.isEmpty(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
