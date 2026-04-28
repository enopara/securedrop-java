package com.emmanuel.securedrop.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "app_users")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AppUser {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true, length = 100)
	private String username;

	@Column(nullable = false, unique = true, length = 255)
	private String email;

	@Column(nullable = false, length = 255)
	private String passwordHash;

	@Column(nullable = false, columnDefinition = "TEXT")
	private String publicKeyPem;

	@Column(nullable = false, columnDefinition = "TEXT")
	private String encryptedPrivateKeyPem;

	@Column(nullable = false, updatable = false)
	private Instant createdAt = Instant.now();

	public static AppUser register(
			String username,
			String email,
			String passwordHash,
			String publicKeyPem,
			String encryptedPrivateKeyPem) {
		AppUser user = new AppUser();
		user.setUsername(username);
		user.setEmail(email);
		user.setPasswordHash(passwordHash);
		user.setPublicKeyPem(publicKeyPem);
		user.setEncryptedPrivateKeyPem(encryptedPrivateKeyPem);
		return user;
	}
}
