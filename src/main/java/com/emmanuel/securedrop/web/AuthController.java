package com.emmanuel.securedrop.web;

import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.security.JwtService;
import com.emmanuel.securedrop.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final UserService userService;
	private final JwtService jwtService;

	public AuthController(UserService userService, JwtService jwtService) {
		this.userService = userService;
		this.jwtService = jwtService;
	}

	@PostMapping("/register")
	public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
		UserService.RegistrationResult result = userService.register(
				request.username(),
				request.email(),
				request.password());
		return RegisterResponse.from(result);
	}

	@PostMapping("/login")
	public LoginResponse login(@Valid @RequestBody LoginRequest request) {
		AppUser user = userService.authenticate(request.username(), request.password());
		JwtService.IssuedToken issuedToken = jwtService.issueToken(user.getUsername());
		return new LoginResponse(user.getId(), user.getUsername(), issuedToken.token(), "Bearer", issuedToken.expiresAt());
	}

	public record RegisterRequest(
			@NotBlank String username,
			@NotBlank @Email String email,
			@NotBlank @Size(min = 8) String password) {
	}

	public record RegisterResponse(Long id, String username, String email, String publicKeyPem) {

		private static RegisterResponse from(UserService.RegistrationResult result) {
			return new RegisterResponse(
					result.id(),
					result.username(),
					result.email(),
					result.publicKeyPem());
		}
	}

	public record LoginRequest(
			@NotBlank String username,
			@NotBlank String password) {
	}

	public record LoginResponse(Long id, String username, String token, String tokenType, Instant expiresAt) {
	}
}
