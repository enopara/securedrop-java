package com.emmanuel.securedrop.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.repository.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

	@Mock
	private AppUserRepository appUserRepository;

	private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	private UserService userService;

	@BeforeEach
	void setUp() {
		userService = new UserService(appUserRepository, passwordEncoder);
		when(appUserRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
	}

	@Test
	void registerHashesPasswordAndStoresEncryptedPrivateKey() {
		String rawPassword = "correct-horse-password";

		UserService.RegistrationResult result = userService.register(
				"alice",
				"alice@example.com",
				rawPassword);

		ArgumentCaptor<AppUser> userCaptor = ArgumentCaptor.forClass(AppUser.class);
		verify(appUserRepository).save(userCaptor.capture());
		AppUser savedUser = userCaptor.getValue();

		assertNotEquals(rawPassword, savedUser.getPasswordHash());
		assertTrue(passwordEncoder.matches(rawPassword, savedUser.getPasswordHash()));
		assertTrue(result.publicKeyPem().contains("BEGIN PUBLIC KEY"));
		assertTrue(savedUser.getEncryptedPrivateKeyPem().contains("BEGIN SECUREDROP ENCRYPTED PRIVATE KEY"));
		assertFalse(savedUser.getEncryptedPrivateKeyPem().contains("BEGIN PRIVATE KEY"));
		assertNotNull(userService.unlockPrivateKey(savedUser, rawPassword));
	}
}
