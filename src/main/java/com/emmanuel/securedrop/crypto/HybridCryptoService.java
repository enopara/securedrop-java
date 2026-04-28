package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class HybridCryptoService {

	private static final byte[] REUSED_GCM_NONCE = new byte[AesGcmCryptoUtil.ivSizeBytes()];
	private static final long WEAK_RANDOM_SEED = 20_260_428L;
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final CryptoPolicy cryptoPolicy;
	private final Random weakRandom = new Random(WEAK_RANDOM_SEED);
	private final SecretKey reusedAesKey = generateReusableAesKey();

	public HybridCryptoService(CryptoPolicy cryptoPolicy) {
		this.cryptoPolicy = cryptoPolicy;
	}

	public EncryptedPackage encryptForRecipient(byte[] plaintext, PublicKey recipientPublicKey)
			throws GeneralSecurityException {
		SecretKey aesKey = chooseAesKey();
		byte[] iv = chooseIv();
		AesGcmCryptoUtil.EncryptedPayload encryptedPayload = AesGcmCryptoUtil.encrypt(plaintext, aesKey, iv);
		byte[] wrappedAesKey = wrapAesKey(aesKey, recipientPublicKey);

		return new EncryptedPackage(
				encryptedPayload.iv(),
				encryptedPayload.ciphertext(),
				wrappedAesKey,
				cryptoPolicy.mistakeMode(),
				sha256Hex(aesKey.getEncoded()));
	}

	public byte[] decryptForRecipient(EncryptedPackage encryptedPackage, PrivateKey recipientPrivateKey)
			throws GeneralSecurityException {
		SecretKey aesKey = unwrapAesKey(encryptedPackage.wrappedAesKey(), recipientPrivateKey);
		AesGcmCryptoUtil.EncryptedPayload encryptedPayload = new AesGcmCryptoUtil.EncryptedPayload(
				encryptedPackage.iv(),
				encryptedPackage.ciphertext());

		if (cryptoPolicy.is(CryptoMistakeMode.SKIP_TAG_VERIFICATION)) {
			return AesGcmCryptoUtil.decryptWithoutVerifyingTag(encryptedPayload, aesKey);
		}

		return AesGcmCryptoUtil.decrypt(encryptedPayload, aesKey);
	}

	public CryptoMistakeMode activeMode() {
		return cryptoPolicy.mistakeMode();
	}

	private SecretKey chooseAesKey() throws GeneralSecurityException {
		if (cryptoPolicy.is(CryptoMistakeMode.AES_KEY_REUSE)) {
			return reusedAesKey;
		}
		if (cryptoPolicy.is(CryptoMistakeMode.WEAK_RANDOM)) {
			return AesGcmCryptoUtil.keyFromBytes(nextWeakBytes(AesGcmCryptoUtil.keySizeBytes()));
		}
		return AesGcmCryptoUtil.generateKey();
	}

	private byte[] chooseIv() {
		if (cryptoPolicy.is(CryptoMistakeMode.NONCE_REUSE)) {
			return REUSED_GCM_NONCE.clone();
		}
		if (cryptoPolicy.is(CryptoMistakeMode.WEAK_RANDOM)) {
			return nextWeakBytes(AesGcmCryptoUtil.ivSizeBytes());
		}

		byte[] iv = new byte[AesGcmCryptoUtil.ivSizeBytes()];
		SECURE_RANDOM.nextBytes(iv);
		return iv;
	}

	private byte[] wrapAesKey(SecretKey aesKey, PublicKey recipientPublicKey) throws GeneralSecurityException {
		if (cryptoPolicy.is(CryptoMistakeMode.INSECURE_RSA_PADDING)) {
			return RsaOaepKeyWrapUtil.wrapAesKeyWithPkcs1Padding(aesKey, recipientPublicKey);
		}
		return RsaOaepKeyWrapUtil.wrapAesKey(aesKey, recipientPublicKey);
	}

	private SecretKey unwrapAesKey(byte[] wrappedAesKey, PrivateKey recipientPrivateKey)
			throws GeneralSecurityException {
		if (cryptoPolicy.is(CryptoMistakeMode.INSECURE_RSA_PADDING)) {
			return RsaOaepKeyWrapUtil.unwrapAesKeyWithPkcs1Padding(wrappedAesKey, recipientPrivateKey);
		}
		return RsaOaepKeyWrapUtil.unwrapAesKey(wrappedAesKey, recipientPrivateKey);
	}

	private synchronized byte[] nextWeakBytes(int size) {
		byte[] bytes = new byte[size];
		weakRandom.nextBytes(bytes);
		return bytes;
	}

	private SecretKey generateReusableAesKey() {
		try {
			return AesGcmCryptoUtil.generateKey();
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create reusable demo AES key", ex);
		}
	}

	private String sha256Hex(byte[] bytes) throws GeneralSecurityException {
		return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
	}

	public record EncryptedPackage(
			byte[] iv,
			byte[] ciphertext,
			byte[] wrappedAesKey,
			CryptoMistakeMode mode,
			String demoAesKeyFingerprint) {
	}
}
