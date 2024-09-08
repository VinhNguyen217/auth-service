package com.java.auth_service.service;

import java.text.ParseException;
import java.util.Date;

import com.java.auth_service.dto.request.AuthenticationRequest;
import com.java.auth_service.dto.request.IntrospectRequest;
import com.java.auth_service.dto.request.LogoutRequest;
import com.java.auth_service.dto.request.RefreshRequest;
import com.java.auth_service.dto.response.AuthenticationResponse;
import com.java.auth_service.dto.response.IntrospectResponse;
import com.java.auth_service.entity.InvalidatedToken;
import com.java.auth_service.exception.AppException;
import com.java.auth_service.exception.ErrorCode;
import com.java.auth_service.repo.InvalidatedTokenRepository;
import com.java.auth_service.repo.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.*;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationService {

    UserRepository userRepository;
    InvalidatedTokenRepository invalidatedTokenRepository;
    PasswordEncoder passwordEncoder;
    JwtTokenProvider jwtTokenProvider;

    public IntrospectResponse introspect(IntrospectRequest request)
            throws JOSEException, ParseException {
        var token = request.getToken();
        boolean isValid = true;

        try {
            jwtTokenProvider.verifyToken(token, false);
        } catch (AppException e) {
            isValid = false;
        }

        return IntrospectResponse.builder()
                .valid(isValid)
                .build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        var user = userRepository
                .findByUsername(request.getUsername())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());

        if (!authenticated) throw new AppException(ErrorCode.UNAUTHENTICATED);

        var token = jwtTokenProvider.generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true).build();
    }

    public void logout(LogoutRequest request)
            throws ParseException, JOSEException {
        var signToken = jwtTokenProvider.verifyToken(request.getToken(), true);

        String jwtID = signToken.getJWTClaimsSet().getJWTID();
        Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken = InvalidatedToken.builder()
                .id(jwtID)
                .expiryTime(expiryTime)
                .build();

        invalidatedTokenRepository.save(invalidatedToken);
    }

    /**
     * Refresh Token
     *
     * @param request
     * @return
     * @throws ParseException
     * @throws JOSEException
     */
    public AuthenticationResponse refreshToken(RefreshRequest request)
            throws ParseException, JOSEException {
        // Xác minh lại Token
        var signedJWT = jwtTokenProvider.verifyToken(request.getToken(), true);

        // Thực hiện lưu token này vào bảng InvalidatedToken
        var jit = signedJWT.getJWTClaimsSet().getJWTID();
        var expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        InvalidatedToken invalidatedToken =
                InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();
        invalidatedTokenRepository.save(invalidatedToken);

        // Lấy thông tin username
        var username = signedJWT.getJWTClaimsSet().getSubject();

        // Lấy thông tin User từ username
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.UNAUTHENTICATED));

        // Tạo token mới
        var token = jwtTokenProvider.generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .authenticated(true)
                .build();
    }

}