package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class PrivateKeyEncryptionUtil {

	private static final String AES = "AES";
	private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
	private static final String BEGIN = "-----BEGIN SECUREDROP ENCRYPTED PRIVATE KEY-----";
	private static final String END = "-----END SECUREDROP ENCRYPTED PRIVATE KEY-----";
	private static final int SALT_SIZE_BYTES = 16;
	private static final int PBKDF2_ITERATIONS = 120_000;
	private static final int AES_KEY_SIZE_BITS = 256;
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private PrivateKeyEncryptionUtil() {
	}

	public static String encryptPrivateKey(PrivateKey privateKey, char[] password) throws GeneralSecurityException {
		byte[] salt = new byte[SALT_SIZE_BYTES];
		SECURE_RANDOM.nextBytes(salt);

		SecretKey encryptionKey = deriveAesKey(password, salt);
		AesGcmCryptoUtil.EncryptedPayload encryptedPayload =
				AesGcmCryptoUtil.encrypt(privateKey.getEncoded(), encryptionKey);

		String payload = String.join(
				":",
				"v1",
				Base64.getEncoder().encodeToString(salt),
				Base64.getEncoder().encodeToString(encryptedPayload.iv()),
				Base64.getEncoder().encodeToString(encryptedPayload.ciphertext()));

		return BEGIN + System.lineSeparator()
				+ payload + System.lineSeparator()
				+ END + System.lineSeparator();
	}

	public static PrivateKey decryptPrivateKey(String encryptedPrivateKeyPem, char[] password)
			throws GeneralSecurityException {
		String payload = encryptedPrivateKeyPem
				.replace(BEGIN, "")
				.replace(END, "")
				.replaceAll("\\s", "");
		String[] parts = payload.split(":");
		if (parts.length != 4 || !"v1".equals(parts[0])) {
			throw new GeneralSecurityException("Unsupported encrypted private key format");
		}

		byte[] salt = Base64.getDecoder().decode(parts[1]);
		byte[] iv = Base64.getDecoder().decode(parts[2]);
		byte[] ciphertext = Base64.getDecoder().decode(parts[3]);

		SecretKey encryptionKey = deriveAesKey(password, salt);
		byte[] privateKeyBytes = AesGcmCryptoUtil.decrypt(
				new AesGcmCryptoUtil.EncryptedPayload(iv, ciphertext),
				encryptionKey);
		return KeyPemUtil.privateKeyFromPkcs8(privateKeyBytes);
	}

	private static SecretKey deriveAesKey(char[] password, byte[] salt) throws GeneralSecurityException {
		PBEKeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, AES_KEY_SIZE_BITS);
		try {
			byte[] keyBytes = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM).generateSecret(keySpec).getEncoded();
			return new SecretKeySpec(keyBytes, AES);
		}
		finally {
			keySpec.clearPassword();
		}
	}
}
