package com.emmanuel.securedrop.service;

import com.emmanuel.securedrop.crypto.AesGcmCryptoUtil;
import com.emmanuel.securedrop.crypto.KeyPemUtil;
import com.emmanuel.securedrop.crypto.RsaOaepKeyWrapUtil;
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
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurePackageService {

	private final SecurePackageRepository securePackageRepository;
	private final AppUserRepository appUserRepository;
	private final UserService userService;

	public SecurePackageService(
			SecurePackageRepository securePackageRepository,
			AppUserRepository appUserRepository,
			UserService userService) {
		this.securePackageRepository = securePackageRepository;
		this.appUserRepository = appUserRepository;
		this.userService = userService;
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
			SecretKey aesKey = AesGcmCryptoUtil.generateKey();
			AesGcmCryptoUtil.EncryptedPayload encryptedPayload = AesGcmCryptoUtil.encrypt(
					plaintextMessage.getBytes(StandardCharsets.UTF_8),
					aesKey);
			byte[] wrappedAesKey = RsaOaepKeyWrapUtil.wrapAesKey(aesKey, recipientPublicKey);

			SecurePackage securePackage = SecurePackage.textMessage(
					sender,
					recipient,
					encode(encryptedPayload.ciphertext()),
					encode(encryptedPayload.iv()),
					encode(wrappedAesKey),
					sha256Hex(encryptedPayload.ciphertext()));

			return PackageReceipt.from(securePackageRepository.save(securePackage));
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
			SecretKey aesKey = RsaOaepKeyWrapUtil.unwrapAesKey(
					decode(securePackage.getEncryptedFileKey()),
					recipientPrivateKey);
			byte[] plaintext = AesGcmCryptoUtil.decrypt(
					new AesGcmCryptoUtil.EncryptedPayload(
							decode(securePackage.getMessageNonce()),
							decode(securePackage.getEncryptedMessage())),
					aesKey);

			return new ReadPackage(
					securePackage.getId(),
					securePackage.getSender().getUsername(),
					securePackage.getRecipient().getUsername(),
					new String(plaintext, StandardCharsets.UTF_8),
					securePackage.getCreatedAt());
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

	public record PackageReceipt(Long id, String senderUsername, String recipientUsername, Instant createdAt) {

		private static PackageReceipt from(SecurePackage securePackage) {
			return new PackageReceipt(
					securePackage.getId(),
					securePackage.getSender().getUsername(),
					securePackage.getRecipient().getUsername(),
					securePackage.getCreatedAt());
		}
	}

	public record ReadPackage(
			Long id,
			String senderUsername,
			String recipientUsername,
			String plaintextMessage,
			Instant createdAt) {
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
