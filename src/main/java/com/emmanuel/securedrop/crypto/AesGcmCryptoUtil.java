package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmCryptoUtil {

	private static final String AES = "AES";
	private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final String AES_CTR_TRANSFORMATION = "AES/CTR/NoPadding";
	private static final int AES_KEY_SIZE_BITS = 256;
	private static final int AES_KEY_SIZE_BYTES = AES_KEY_SIZE_BITS / Byte.SIZE;
	private static final int GCM_TAG_SIZE_BITS = 128;
	private static final int GCM_TAG_SIZE_BYTES = GCM_TAG_SIZE_BITS / Byte.SIZE;
	private static final int GCM_IV_SIZE_BYTES = 12;
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private AesGcmCryptoUtil() {
	}

	public static SecretKey generateKey() throws GeneralSecurityException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
		keyGenerator.init(AES_KEY_SIZE_BITS);
		return keyGenerator.generateKey();
	}

	public static SecretKey keyFromBytes(byte[] rawAesKey) {
		return new SecretKeySpec(rawAesKey, AES);
	}

	public static int keySizeBytes() {
		return AES_KEY_SIZE_BYTES;
	}

	public static int ivSizeBytes() {
		return GCM_IV_SIZE_BYTES;
	}

	public static EncryptedPayload encrypt(byte[] plaintext, SecretKey key) throws GeneralSecurityException {
		byte[] iv = new byte[GCM_IV_SIZE_BYTES];
		SECURE_RANDOM.nextBytes(iv);

		return encrypt(plaintext, key, iv);
	}

	public static EncryptedPayload encrypt(byte[] plaintext, SecretKey key, byte[] iv) throws GeneralSecurityException {
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

	public static byte[] decryptWithoutVerifyingTag(EncryptedPayload encryptedPayload, SecretKey key)
			throws GeneralSecurityException {
		if (encryptedPayload.iv().length != GCM_IV_SIZE_BYTES
				|| encryptedPayload.ciphertext().length < GCM_TAG_SIZE_BYTES) {
			throw new GeneralSecurityException("Invalid AES-GCM payload");
		}

		byte[] ciphertextWithoutTag = Arrays.copyOf(
				encryptedPayload.ciphertext(),
				encryptedPayload.ciphertext().length - GCM_TAG_SIZE_BYTES);
		Cipher cipher = Cipher.getInstance(AES_CTR_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(gcmInitialCounterBlock(encryptedPayload.iv())));
		return cipher.doFinal(ciphertextWithoutTag);
	}

	private static byte[] gcmInitialCounterBlock(byte[] iv) {
		byte[] counterBlock = new byte[16];
		System.arraycopy(iv, 0, counterBlock, 0, iv.length);
		counterBlock[15] = 2;
		return counterBlock;
	}

	public record EncryptedPayload(byte[] iv, byte[] ciphertext) {
	}
}
