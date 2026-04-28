package com.emmanuel.securedrop.web;

import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.service.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

	private final UserService userService;

	public AuthController(UserService userService) {
		this.userService = userService;
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
		return new LoginResponse(user.getId(), user.getUsername(), true);
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

	public record LoginResponse(Long id, String username, boolean authenticated) {
	}
}
