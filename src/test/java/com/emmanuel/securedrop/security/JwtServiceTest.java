package com.emmanuel.securedrop.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class JwtServiceTest {

	private final JwtService jwtService = new JwtService(
			new ObjectMapper(),
			"test-signing-secret-that-is-long-enough",
			3600);

	@Test
	void issuedTokenCanBeValidated() {
		JwtService.IssuedToken issuedToken = jwtService.issueToken("alice");

		assertEquals("alice", jwtService.validateAndExtractUsername(issuedToken.token()));
	}

	@Test
	void tamperedTokenIsRejected() {
		JwtService.IssuedToken issuedToken = jwtService.issueToken("alice");
		String tamperedToken = issuedToken.token().substring(0, issuedToken.token().length() - 1) + "x";

		assertThrows(IllegalArgumentException.class, () -> jwtService.validateAndExtractUsername(tamperedToken));
	}
}
