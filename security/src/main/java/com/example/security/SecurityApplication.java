package com.example.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.example.security.entity.Role;
import com.example.security.request.RegisterRequest;
import com.example.security.service.AuthenticationService;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {
		return args -> {
			var admin = RegisterRequest.builder().firstName("Admin").lastName("Admin").email("admin@gmail.com").password("password").role(Role.ADMIN).build();
			System.out.println("Admin token: " + authenticationService.register(admin).getAccessToken());

			var manager = RegisterRequest.builder().firstName("Manager").lastName("Manager").email("manager@gmail.com").password("password").role(Role.MANAGER).build();
			System.out.println("Manager token: " + authenticationService.register(manager).getAccessToken());
		};
	}

}
