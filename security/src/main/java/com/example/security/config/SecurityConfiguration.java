package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import lombok.RequiredArgsConstructor;
import static com.example.security.entity.Role.ADMIN;
import static com.example.security.entity.Role.MANAGER;

import static com.example.security.entity.Permission.ADMIN_READ;
import static com.example.security.entity.Permission.ADMIN_CREATE;
import static com.example.security.entity.Permission.ADMIN_UPDATE;
import static com.example.security.entity.Permission.ADMIN_DELETE;

import static com.example.security.entity.Permission.MANAGER_CREATE;
import static com.example.security.entity.Permission.MANAGER_READ;
import static com.example.security.entity.Permission.MANAGER_UPDATE;
import static com.example.security.entity.Permission.MANAGER_DELETE;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.requestMatchers("/api/v1/auth/**")
                        .permitAll()

                        .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                        .requestMatchers(HttpMethod.GET, "/api/v1/management/**")
                        .hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                        .requestMatchers(HttpMethod.POST, "/api/v1/management/**")
                        .hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                        .requestMatchers(HttpMethod.PUT, "/api/v1/management/**")
                        .hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/management/**")
                        .hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                        // .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())
                        // .requestMatchers(HttpMethod.GET, "/api/v1/admin/**")
                        // .hasAuthority(ADMIN_READ.name())
                        // .requestMatchers(HttpMethod.POST, "/api/v1/admin/**")
                        // .hasAuthority(ADMIN_CREATE.name())
                        // .requestMatchers(HttpMethod.PUT, "/api/v1/admin/**")
                        // .hasAuthority(ADMIN_UPDATE.name())
                        // .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/**")
                        // .hasAuthority(ADMIN_DELETE.name())

                        .anyRequest()
                        .authenticated())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                (request, response, authentication) -> SecurityContextHolder.clearContext()));
        return http.build();
    }
}
