package com.emmanuel.securedrop.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HybridCryptoServiceTest {

	private KeyPair recipientKeyPair;

	@BeforeEach
	void setUp() throws GeneralSecurityException {
		recipientKeyPair = RsaKeyPairGenerator.generateKeyPair();
	}

	@Test
	void secureModeUsesDifferentAesKeysAndNonces() throws GeneralSecurityException {
		HybridCryptoService cryptoService = cryptoService("secure");

		HybridCryptoService.EncryptedPackage first = encrypt(cryptoService, "message one");
		HybridCryptoService.EncryptedPackage second = encrypt(cryptoService, "message two");

		assertNotEquals(first.demoAesKeyFingerprint(), second.demoAesKeyFingerprint());
		assertNotEquals(bytesAsString(first.iv()), bytesAsString(second.iv()));
	}

	@Test
	void nonceReuseModeUsesTheSameNonceAcrossPackages() throws GeneralSecurityException {
		HybridCryptoService cryptoService = cryptoService("nonce-reuse");

		HybridCryptoService.EncryptedPackage first = encrypt(cryptoService, "message one");
		HybridCryptoService.EncryptedPackage second = encrypt(cryptoService, "message two");

		assertArrayEquals(first.iv(), second.iv());
		assertEquals(CryptoMistakeMode.NONCE_REUSE, first.mode());
	}

	@Test
	void weakRandomModeIsPredictableAcrossFreshServiceInstances() throws GeneralSecurityException {
		HybridCryptoService firstService = cryptoService("weak-rng");
		HybridCryptoService secondService = cryptoService("weak-rng");

		HybridCryptoService.EncryptedPackage first = encrypt(firstService, "same plaintext");
		HybridCryptoService.EncryptedPackage second = encrypt(secondService, "same plaintext");

		assertArrayEquals(first.iv(), second.iv());
		assertEquals(first.demoAesKeyFingerprint(), second.demoAesKeyFingerprint());
		assertEquals(CryptoMistakeMode.WEAK_RANDOM, first.mode());
	}

	@Test
	void skipTagVerificationModeReturnsPlaintextEvenWhenTagIsTampered()
			throws GeneralSecurityException {
		HybridCryptoService cryptoService = cryptoService("skip-tag-verification");
		String plaintext = "do not accept tampered messages";
		HybridCryptoService.EncryptedPackage encryptedPackage = encrypt(cryptoService, plaintext);

		HybridCryptoService.EncryptedPackage tamperedPackage = tamperWithFinalTagByte(encryptedPackage);

		byte[] decrypted = cryptoService.decryptForRecipient(tamperedPackage, recipientKeyPair.getPrivate());

		assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
		assertEquals(CryptoMistakeMode.SKIP_TAG_VERIFICATION, encryptedPackage.mode());
	}

	@Test
	void insecureRsaPaddingModeStillDecryptsButUsesBadPaddingChoice()
			throws GeneralSecurityException {
		HybridCryptoService cryptoService = cryptoService("insecure-rsa-padding");
		String plaintext = "rsa padding experiment";

		HybridCryptoService.EncryptedPackage encryptedPackage = encrypt(cryptoService, plaintext);
		byte[] decrypted = cryptoService.decryptForRecipient(encryptedPackage, recipientKeyPair.getPrivate());

		assertEquals(plaintext, new String(decrypted, StandardCharsets.UTF_8));
		assertEquals(CryptoMistakeMode.INSECURE_RSA_PADDING, encryptedPackage.mode());
	}

	@Test
	void aesKeyReuseModeUsesSameAesKeyAcrossPackages() throws GeneralSecurityException {
		HybridCryptoService cryptoService = cryptoService("aes-key-reuse");

		HybridCryptoService.EncryptedPackage first = encrypt(cryptoService, "message one");
		HybridCryptoService.EncryptedPackage second = encrypt(cryptoService, "message two");

		assertEquals(first.demoAesKeyFingerprint(), second.demoAesKeyFingerprint());
		assertEquals(CryptoMistakeMode.AES_KEY_REUSE, first.mode());
	}

	private HybridCryptoService cryptoService(String mode) {
		return new HybridCryptoService(new CryptoPolicy(mode));
	}

	private HybridCryptoService.EncryptedPackage encrypt(HybridCryptoService cryptoService, String plaintext)
			throws GeneralSecurityException {
		return cryptoService.encryptForRecipient(
				plaintext.getBytes(StandardCharsets.UTF_8),
				recipientKeyPair.getPublic());
	}

	private HybridCryptoService.EncryptedPackage tamperWithFinalTagByte(
			HybridCryptoService.EncryptedPackage encryptedPackage) {
		byte[] tamperedCiphertext = encryptedPackage.ciphertext().clone();
		tamperedCiphertext[tamperedCiphertext.length - 1] =
				(byte) (tamperedCiphertext[tamperedCiphertext.length - 1] ^ 1);
		return new HybridCryptoService.EncryptedPackage(
				encryptedPackage.iv(),
				tamperedCiphertext,
				encryptedPackage.wrappedAesKey(),
				encryptedPackage.mode(),
				encryptedPackage.demoAesKeyFingerprint());
	}

	private String bytesAsString(byte[] bytes) {
		return java.util.HexFormat.of().formatHex(bytes);
	}
}
