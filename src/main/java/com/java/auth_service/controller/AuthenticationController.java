package com.java.auth_service.controller;

import java.text.ParseException;

import com.java.auth_service.dto.request.AuthenticationRequest;
import com.java.auth_service.dto.request.IntrospectRequest;
import com.java.auth_service.dto.request.LogoutRequest;
import com.java.auth_service.dto.response.ApiResponse;
import com.java.auth_service.service.AuthenticationService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.nimbusds.jose.JOSEException;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;

    @PostMapping("/login")
    ApiResponse<?> authenticate(@RequestBody AuthenticationRequest request) {
        return ApiResponse.builder()
                .result(authenticationService.login(request))
                .build();
    }

    @PostMapping("/introspect")
    ApiResponse<?> authenticate(@RequestBody IntrospectRequest request)
            throws ParseException, JOSEException {
        return ApiResponse.builder()
                .result(authenticationService.introspect(request))
                .build();
    }

//    @PostMapping("/refresh")
//    ApiResponse<AuthenticationResponse> authenticate(@RequestBody RefreshRequest request)
//            throws ParseException, JOSEException {
//        var result = authenticationService.refreshToken(request);
//        return ApiResponse.<AuthenticationResponse>builder().result(result).build();
//    }

    @PostMapping("/logout")
    ApiResponse<Void> logout(@RequestBody LogoutRequest request) throws ParseException, JOSEException {
        authenticationService.logout(request);
        return ApiResponse.<Void>builder().build();
    }
}