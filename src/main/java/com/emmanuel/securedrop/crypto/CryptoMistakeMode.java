package com.emmanuel.securedrop.crypto;

import java.util.Arrays;

public enum CryptoMistakeMode {

	SECURE("secure"),
	NONCE_REUSE("nonce-reuse"),
	WEAK_RANDOM("weak-rng"),
	SKIP_TAG_VERIFICATION("skip-tag-verification"),
	INSECURE_RSA_PADDING("insecure-rsa-padding"),
	AES_KEY_REUSE("aes-key-reuse");

	private final String propertyValue;

	CryptoMistakeMode(String propertyValue) {
		this.propertyValue = propertyValue;
	}

	public String propertyValue() {
		return propertyValue;
	}

	public static CryptoMistakeMode fromProperty(String value) {
		String normalized = value == null ? "" : value.trim();
		String enumStyle = normalized.replace("-", "_");
		String propertyStyle = normalized.replace("_", "-");
		return Arrays.stream(values())
				.filter(mode -> mode.name().equalsIgnoreCase(enumStyle)
						|| mode.propertyValue.equalsIgnoreCase(propertyStyle))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException("Unsupported crypto mistake mode: " + value));
	}
}
