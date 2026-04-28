package com.emmanuel.securedrop.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.domain.SecurePackage;
import com.emmanuel.securedrop.repository.AppUserRepository;
import com.emmanuel.securedrop.repository.SecurePackageRepository;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class SecurePackageServiceTest {

	@Mock
	private SecurePackageRepository securePackageRepository;

	@Mock
	private AppUserRepository appUserRepository;

	private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
	private final List<AppUser> registeredUsers = new ArrayList<>();
	private final AtomicReference<SecurePackage> savedPackage = new AtomicReference<>();
	private UserService userService;
	private SecurePackageService securePackageService;

	@BeforeEach
	void setUp() {
		userService = new UserService(appUserRepository, passwordEncoder);
		securePackageService = new SecurePackageService(securePackageRepository, appUserRepository, userService);

		when(appUserRepository.save(any(AppUser.class))).thenAnswer(invocation -> {
			AppUser user = invocation.getArgument(0);
			user.setId((long) registeredUsers.size() + 1);
			registeredUsers.add(user);
			return user;
		});
		when(securePackageRepository.save(any(SecurePackage.class))).thenAnswer(invocation -> {
			SecurePackage securePackage = invocation.getArgument(0);
			securePackage.setId(1L);
			savedPackage.set(securePackage);
			return securePackage;
		});
		when(securePackageRepository.findById(1L)).thenAnswer(invocation -> Optional.ofNullable(savedPackage.get()));
	}

	@Test
	void sendAndReadTextPackageUsesHybridEncryptionAndRejectsTampering() {
		AppUser alice = registerUser("alice", "alice@example.com", "alice-password");
		AppUser bob = registerUser("bob", "bob@example.com", "bob-password");
		when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(alice));
		when(appUserRepository.findByUsername("bob")).thenReturn(Optional.of(bob));

		String plaintext = "Meet at 10. Bring the incident report.";

		SecurePackageService.PackageReceipt receipt = securePackageService.sendTextPackage("alice", "bob", plaintext);
		SecurePackage persistedPackage = savedPackage.get();

		assertEquals(1L, receipt.id());
		assertNotNull(persistedPackage.getEncryptedMessage());
		assertNotNull(persistedPackage.getMessageNonce());
		assertNotNull(persistedPackage.getEncryptedFileKey());
		assertFalse(persistedPackage.getEncryptedMessage().contains(plaintext));

		SecurePackageService.ReadPackage readPackage =
				securePackageService.readTextPackage(1L, "bob", "bob-password");
		assertEquals(plaintext, readPackage.plaintextMessage());

		tamperWithCiphertext(persistedPackage);

		assertThrows(
				IllegalStateException.class,
				() -> securePackageService.readTextPackage(1L, "bob", "bob-password"));
	}

	private AppUser registerUser(String username, String email, String password) {
		int indexBeforeRegister = registeredUsers.size();
		userService.register(username, email, password);
		return registeredUsers.get(indexBeforeRegister);
	}

	private void tamperWithCiphertext(SecurePackage securePackage) {
		byte[] ciphertext = Base64.getDecoder().decode(securePackage.getEncryptedMessage());
		ciphertext[ciphertext.length - 1] = (byte) (ciphertext[ciphertext.length - 1] ^ 1);
		securePackage.setEncryptedMessage(Base64.getEncoder().encodeToString(ciphertext));
	}
}
