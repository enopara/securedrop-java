package com.emmanuel.securedrop.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder BASE64_URL_DECODER = Base64.getUrlDecoder();
	private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
	};

	private final ObjectMapper objectMapper;
	private final byte[] signingSecret;
	private final long expirationSeconds;

	public JwtService(
			ObjectMapper objectMapper,
			@Value("${securedrop.jwt.secret}") String signingSecret,
			@Value("${securedrop.jwt.expiration-seconds}") long expirationSeconds) {
		this.objectMapper = objectMapper;
		this.signingSecret = signingSecret.getBytes(StandardCharsets.UTF_8);
		this.expirationSeconds = expirationSeconds;
	}

	public IssuedToken issueToken(String username) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(expirationSeconds);

		Map<String, Object> header = new LinkedHashMap<>();
		header.put("alg", "HS256");
		header.put("typ", "JWT");

		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("sub", username);
		payload.put("iat", issuedAt.getEpochSecond());
		payload.put("exp", expiresAt.getEpochSecond());

		String unsignedToken = encodeJson(header) + "." + encodeJson(payload);
		String signature = sign(unsignedToken);
		return new IssuedToken(unsignedToken + "." + signature, expiresAt);
	}

	public String validateAndExtractUsername(String token) {
		String[] parts = token.split("\\.");
		if (parts.length != 3) {
			throw new IllegalArgumentException("Invalid JWT format");
		}

		String unsignedToken = parts[0] + "." + parts[1];
		if (!MessageDigest.isEqual(sign(unsignedToken).getBytes(StandardCharsets.UTF_8),
				parts[2].getBytes(StandardCharsets.UTF_8))) {
			throw new IllegalArgumentException("Invalid JWT signature");
		}

		Map<String, Object> payload = decodeJson(parts[1]);
		String username = (String) payload.get("sub");
		Number expiresAt = (Number) payload.get("exp");
		if (username == null || username.isBlank() || expiresAt == null) {
			throw new IllegalArgumentException("Invalid JWT claims");
		}
		if (Instant.now().getEpochSecond() >= expiresAt.longValue()) {
			throw new IllegalArgumentException("JWT has expired");
		}

		return username;
	}

	private String encodeJson(Map<String, Object> value) {
		try {
			return BASE64_URL_ENCODER.encodeToString(objectMapper.writeValueAsBytes(value));
		}
		catch (JsonProcessingException ex) {
			throw new IllegalStateException("Could not encode JWT JSON", ex);
		}
	}

	private Map<String, Object> decodeJson(String encodedJson) {
		try {
			return objectMapper.readValue(BASE64_URL_DECODER.decode(encodedJson), MAP_TYPE);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException("Could not decode JWT JSON", ex);
		}
	}

	private String sign(String unsignedToken) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			mac.init(new SecretKeySpec(signingSecret, HMAC_ALGORITHM));
			return BASE64_URL_ENCODER.encodeToString(mac.doFinal(unsignedToken.getBytes(StandardCharsets.UTF_8)));
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not sign JWT", ex);
		}
	}

	public record IssuedToken(String token, Instant expiresAt) {
	}
}
