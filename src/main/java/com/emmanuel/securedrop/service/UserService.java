package com.emmanuel.securedrop.service;

import com.emmanuel.securedrop.crypto.KeyPemUtil;
import com.emmanuel.securedrop.crypto.PrivateKeyEncryptionUtil;
import com.emmanuel.securedrop.crypto.RsaKeyPairGenerator;
import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.repository.AppUserRepository;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;

	public UserService(AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
		this.appUserRepository = appUserRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Transactional
	public RegistrationResult register(String username, String email, String password) {
		validateRegistration(username, email, password);

		try {
			String passwordHash = passwordEncoder.encode(password);
			KeyPair keyPair = RsaKeyPairGenerator.generateKeyPair();
			String publicKeyPem = KeyPemUtil.publicKeyToPem(keyPair.getPublic());
			char[] passwordChars = password.toCharArray();
			String encryptedPrivateKeyPem;
			try {
				encryptedPrivateKeyPem = PrivateKeyEncryptionUtil.encryptPrivateKey(
						keyPair.getPrivate(),
						passwordChars);
			}
			finally {
				Arrays.fill(passwordChars, '\0');
			}

			AppUser savedUser = appUserRepository.save(AppUser.register(
					username,
					email,
					passwordHash,
					publicKeyPem,
					encryptedPrivateKeyPem));

			return RegistrationResult.from(savedUser);
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not register user because key generation failed", ex);
		}
	}

	@Transactional(readOnly = true)
	public AppUser authenticate(String username, String password) {
		AppUser user = findByUsername(username);
		if (!passwordEncoder.matches(password, user.getPasswordHash())) {
			throw new IllegalArgumentException("Invalid username or password");
		}
		return user;
	}

	@Transactional(readOnly = true)
	public PrivateKey unlockPrivateKey(AppUser user, String password) {
		if (!passwordEncoder.matches(password, user.getPasswordHash())) {
			throw new IllegalArgumentException("Invalid username or password");
		}

		try {
			char[] passwordChars = password.toCharArray();
			try {
				return PrivateKeyEncryptionUtil.decryptPrivateKey(
						user.getEncryptedPrivateKeyPem(),
						passwordChars);
			}
			finally {
				Arrays.fill(passwordChars, '\0');
			}
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not decrypt private key", ex);
		}
	}

	@Transactional(readOnly = true)
	public AppUser findByUsername(String username) {
		return appUserRepository.findByUsername(username)
				.orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
	}

	private void validateRegistration(String username, String email, String password) {
		if (isBlank(username)) {
			throw new IllegalArgumentException("Username is required");
		}
		if (isBlank(email)) {
			throw new IllegalArgumentException("Email is required");
		}
		if (password == null || password.length() < 8) {
			throw new IllegalArgumentException("Password must be at least 8 characters");
		}
		if (appUserRepository.existsByUsername(username)) {
			throw new IllegalArgumentException("Username is already registered");
		}
		if (appUserRepository.existsByEmail(email)) {
			throw new IllegalArgumentException("Email is already registered");
		}
	}

	private boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	public record RegistrationResult(Long id, String username, String email, String publicKeyPem) {

		private static RegistrationResult from(AppUser user) {
			return new RegistrationResult(
					user.getId(),
					user.getUsername(),
					user.getEmail(),
					user.getPublicKeyPem());
		}
	}
}
