package com.emmanuel.securedrop.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public final class RsaKeyPairGenerator {

	private static final String RSA = "RSA";
	private static final int RSA_KEY_SIZE_BITS = 3072;

	private RsaKeyPairGenerator() {
	}

	public static KeyPair generateKeyPair() throws GeneralSecurityException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
		keyPairGenerator.initialize(RSA_KEY_SIZE_BITS);
		return keyPairGenerator.generateKeyPair();
	}
}
