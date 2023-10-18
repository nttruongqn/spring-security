package com.example.security.controller;

import java.io.IOException;
import java.security.Principal;

import org.apache.catalina.connector.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.request.AuthenticationRequest;
import com.example.security.request.ChangePasswordRequest;
import com.example.security.request.RegisterRequest;
import com.example.security.request.VerificactionRequest;
import com.example.security.response.AuthenticationResponse;
import com.example.security.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        var response = authenticationService.register(request);
        if(request.isMfaEnabled()) {
        return ResponseEntity.ok(response);
        }
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authenticationService.refreshToken(request, response);
    }

     @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@RequestBody VerificactionRequest verificactionRequest) {
        return ResponseEntity.ok(authenticationService.verifyCode(verificactionRequest));
    }

    @PatchMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest,
            Principal connectedUser) {
        authenticationService.changePassword(changePasswordRequest, connectedUser);
        return ResponseEntity.ok().build();
    }
    

}
