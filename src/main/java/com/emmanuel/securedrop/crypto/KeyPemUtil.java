package com.emmanuel.securedrop.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class KeyPemUtil {

	private static final String RSA = "RSA";
	private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
	private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";
	private static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
	private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

	private KeyPemUtil() {
	}

	public static String publicKeyToPem(PublicKey publicKey) {
		return toPem(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, publicKey.getEncoded());
	}

	public static PublicKey publicKeyFromPem(String publicKeyPem) throws GeneralSecurityException {
		byte[] keyBytes = parsePem(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, publicKeyPem);
		return KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(keyBytes));
	}

	public static String privateKeyToPem(PrivateKey privateKey) {
		return toPem(PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, privateKey.getEncoded());
	}

	public static PrivateKey privateKeyFromPem(String privateKeyPem) throws GeneralSecurityException {
		return privateKeyFromPkcs8(parsePem(PRIVATE_KEY_BEGIN, PRIVATE_KEY_END, privateKeyPem));
	}

	public static PrivateKey privateKeyFromPkcs8(byte[] privateKeyBytes) throws GeneralSecurityException {
		return KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
	}

	private static String toPem(String begin, String end, byte[] keyBytes) {
		String encoded = Base64.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII))
				.encodeToString(keyBytes);
		return begin + System.lineSeparator()
				+ encoded + System.lineSeparator()
				+ end + System.lineSeparator();
	}

	private static byte[] parsePem(String begin, String end, String pem) {
		String encoded = pem
				.replace(begin, "")
				.replace(end, "")
				.replaceAll("\\s", "");
		return Base64.getDecoder().decode(encoded);
	}
}
