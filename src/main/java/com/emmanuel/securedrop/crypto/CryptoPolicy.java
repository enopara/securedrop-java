package com.emmanuel.securedrop.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CryptoPolicy {

	private final CryptoMistakeMode mistakeMode;

	public CryptoPolicy(@Value("${securedrop.crypto.mistake-mode:secure}") String mistakeMode) {
		this.mistakeMode = CryptoMistakeMode.fromProperty(mistakeMode);
	}

	public CryptoMistakeMode mistakeMode() {
		return mistakeMode;
	}

	public boolean is(CryptoMistakeMode expectedMode) {
		return mistakeMode == expectedMode;
	}
}
