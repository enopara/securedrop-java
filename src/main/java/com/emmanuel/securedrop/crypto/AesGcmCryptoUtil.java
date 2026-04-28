package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class AesGcmCryptoUtil {

	private static final String AES = "AES";
	private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final int AES_KEY_SIZE_BITS = 256;
	private static final int GCM_TAG_SIZE_BITS = 128;
	private static final int GCM_IV_SIZE_BYTES = 12;
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private AesGcmCryptoUtil() {
	}

	public static SecretKey generateKey() throws GeneralSecurityException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(AES_KEY_SIZE_BITS);
		return keyGenerator.generateKey();
	}

	public static EncryptedPayload encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
		byte[] iv = new byte[GCM_IV_SIZE_BYTES];
		SECURE_RANDOM.nextBytes(iv);

		Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv));

		return new EncryptedPayload(iv, cipher.doFinal(plaintext));
	}

	public static byte[] decrypt(EncryptedPayload encryptedPayload, SecretKey key) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
		cipher.init(
				Cipher.DECRYPT_MODE,
				key,
				new GCMParameterSpec(GCM_TAG_SIZE_BITS, encryptedPayload.iv()));

		return cipher.doFinal(encryptedPayload.ciphertext());
	}

	public record EncryptedPayload(byte[] iv, byte[] ciphertext) {
	}
}
