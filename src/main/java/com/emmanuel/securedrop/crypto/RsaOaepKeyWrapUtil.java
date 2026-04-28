package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public final class RsaOaepKeyWrapUtil {

	private static final String AES = "AES";
	private static final String RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	private static final OAEPParameterSpec OAEP_SHA256_SPEC = new OAEPParameterSpec(
			"SHA-256",
			"MGF1",
			MGF1ParameterSpec.SHA256,
			PSource.PSpecified.DEFAULT);

	private RsaOaepKeyWrapUtil() {
	}

	public static byte[] wrapAesKey(SecretKey aesKey, PublicKey publicKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION);
		cipher.init(Cipher.WRAP_MODE, publicKey, OAEP_SHA256_SPEC);
		return cipher.wrap(aesKey);
	}

	public static SecretKey unwrapAesKey(byte[] wrappedAesKey, PrivateKey privateKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION);
		cipher.init(Cipher.UNWRAP_MODE, privateKey, OAEP_SHA256_SPEC);
		return (SecretKey) cipher.unwrap(wrappedAesKey, AES, Cipher.SECRET_KEY);
	}

	public static SecretKey aesKeyFromBytes(byte[] rawAesKey) {
		return new SecretKeySpec(rawAesKey, AES);
	}
}
