package com.example.security.service;

import java.io.IOException;
import java.security.Principal;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.security.entity.Role;
import com.example.security.entity.Token;
import com.example.security.entity.TokenType;
import com.example.security.entity.User;
import com.example.security.repository.TokenRepository;
import com.example.security.repository.UserRepository;
import com.example.security.request.AuthenticationRequest;
import com.example.security.request.ChangePasswordRequest;
import com.example.security.request.RegisterRequest;
import com.example.security.request.VerificactionRequest;
import com.example.security.response.AuthenticationResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorAuthenticationService twoFactorAuthenticationService;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ADMIN)
                .mfaEnabled(request.isMfaEnabled())
                .build();
        if (request.isMfaEnabled()) {
            user.setSecret(twoFactorAuthenticationService.generateNewSecret());
        }

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .secretImageUri(twoFactorAuthenticationService.generateQrCodeImageUri(user.getSecret()))
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder().user(user).token(jwtToken).tokenType(TokenType.BEARER)
                .expired(false).revoked(false).build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;

        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        if (user.isMfaEnabled()) {
            return AuthenticationResponse.builder()
                    .accessToken("")
                    .refreshToken("")
                    .mfaEnabled(true)
                    .build();
        }
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(false)
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userRepository.findByEmail(userEmail).orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                var accessToken = jwtService.generateToken(user);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .mfaEnabled(false)
                        .build();
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }

    public void changePassword(ChangePasswordRequest changePasswordRequest, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();
        if (!passwordEncoder.matches(changePasswordRequest.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        if (!changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }
        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
        userRepository.save(user);
    }

    public AuthenticationResponse verifyCode(VerificactionRequest verificactionRequest) {
        User user = userRepository.findByEmail(verificactionRequest.getEmail())
        .orElseThrow(() -> new EntityNotFoundException(String.format("No user found with %S", verificactionRequest.getEmail())));
        if(twoFactorAuthenticationService.isOtpValid(user.getSecret(), verificactionRequest.getCode())) {
            throw new BadCredentialsException("Code is not correct.");
        };
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).mfaEnabled(user.isMfaEnabled()).build();
    }

}
