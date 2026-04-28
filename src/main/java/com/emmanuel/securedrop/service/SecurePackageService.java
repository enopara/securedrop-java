package com.emmanuel.securedrop.service;

import com.emmanuel.securedrop.crypto.HybridCryptoService;
import com.emmanuel.securedrop.crypto.KeyPemUtil;
import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.domain.SecurePackage;
import com.emmanuel.securedrop.repository.AppUserRepository;
import com.emmanuel.securedrop.repository.SecurePackageRepository;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurePackageService {

	private final SecurePackageRepository securePackageRepository;
	private final AppUserRepository appUserRepository;
	private final UserService userService;
	private final HybridCryptoService hybridCryptoService;

	public SecurePackageService(
			SecurePackageRepository securePackageRepository,
			AppUserRepository appUserRepository,
			UserService userService,
			HybridCryptoService hybridCryptoService) {
		this.securePackageRepository = securePackageRepository;
		this.appUserRepository = appUserRepository;
		this.userService = userService;
		this.hybridCryptoService = hybridCryptoService;
	}

	@Transactional
	public PackageReceipt sendTextPackage(String senderUsername, String recipientUsername, String plaintextMessage) {
		if (isBlank(plaintextMessage)) {
			throw new IllegalArgumentException("Message is required");
		}

		AppUser sender = findUser(senderUsername);
		AppUser recipient = findUser(recipientUsername);

		try {
			PublicKey recipientPublicKey = KeyPemUtil.publicKeyFromPem(recipient.getPublicKeyPem());
			HybridCryptoService.EncryptedPackage encryptedPackage = hybridCryptoService.encryptForRecipient(
					plaintextMessage.getBytes(StandardCharsets.UTF_8),
					recipientPublicKey);

			SecurePackage securePackage = SecurePackage.textMessage(
					sender,
					recipient,
					encode(encryptedPackage.ciphertext()),
					encode(encryptedPackage.iv()),
					encode(encryptedPackage.wrappedAesKey()),
					sha256Hex(encryptedPackage.ciphertext()));

			return PackageReceipt.from(
					securePackageRepository.save(securePackage),
					hybridCryptoService.activeMode().propertyValue());
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not encrypt secure package", ex);
		}
	}

	@Transactional(readOnly = true)
	public ReadPackage readTextPackage(Long packageId, String recipientUsername, String recipientPassword) {
		SecurePackage securePackage = securePackageRepository.findById(packageId)
				.orElseThrow(() -> new IllegalArgumentException("Package not found: " + packageId));

		if (!securePackage.getRecipient().getUsername().equals(recipientUsername)) {
			throw new IllegalArgumentException("Package does not belong to recipient: " + recipientUsername);
		}

		try {
			PrivateKey recipientPrivateKey = userService.unlockPrivateKey(securePackage.getRecipient(), recipientPassword);
			byte[] plaintext = hybridCryptoService.decryptForRecipient(
					new HybridCryptoService.EncryptedPackage(
							decode(securePackage.getMessageNonce()),
							decode(securePackage.getEncryptedMessage()),
							decode(securePackage.getEncryptedFileKey()),
							hybridCryptoService.activeMode(),
							"not-exposed"),
					recipientPrivateKey);

			return new ReadPackage(
					securePackage.getId(),
					securePackage.getSender().getUsername(),
					securePackage.getRecipient().getUsername(),
					new String(plaintext, StandardCharsets.UTF_8),
					securePackage.getCreatedAt(),
					hybridCryptoService.activeMode().propertyValue());
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not decrypt secure package", ex);
		}
	}

	@Transactional(readOnly = true)
	public List<PackageSummary> inbox(String recipientUsername) {
		AppUser recipient = findUser(recipientUsername);
		return securePackageRepository.findByRecipient(recipient)
				.stream()
				.map(PackageSummary::from)
				.toList();
	}

	private AppUser findUser(String username) {
		return appUserRepository.findByUsername(username)
				.orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
	}

	private boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private String encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	private byte[] decode(String value) {
		return Base64.getDecoder().decode(value);
	}

	private String sha256Hex(byte[] bytes) throws GeneralSecurityException {
		return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
	}

	public record PackageReceipt(
			Long id,
			String senderUsername,
			String recipientUsername,
			Instant createdAt,
			String cryptoMode) {

		private static PackageReceipt from(SecurePackage securePackage, String cryptoMode) {
			return new PackageReceipt(
					securePackage.getId(),
					securePackage.getSender().getUsername(),
					securePackage.getRecipient().getUsername(),
					securePackage.getCreatedAt(),
					cryptoMode);
		}
	}

	public record ReadPackage(
			Long id,
			String senderUsername,
			String recipientUsername,
			String plaintextMessage,
			Instant createdAt,
			String cryptoMode) {
	}

	public record PackageSummary(Long id, String senderUsername, String recipientUsername, Instant createdAt) {

		private static PackageSummary from(SecurePackage securePackage) {
			return new PackageSummary(
					securePackage.getId(),
					securePackage.getSender().getUsername(),
					securePackage.getRecipient().getUsername(),
					securePackage.getCreatedAt());
		}
	}
}
