package com.emmanuel.securedrop.web;

import com.emmanuel.securedrop.service.SecurePackageService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/packages")
public class SecurePackageController {

	private final SecurePackageService securePackageService;

	public SecurePackageController(SecurePackageService securePackageService) {
		this.securePackageService = securePackageService;
	}

	@PostMapping("/send")
	public PackageReceiptResponse send(Authentication authentication, @Valid @RequestBody SendPackageRequest request) {
		SecurePackageService.PackageReceipt receipt = securePackageService.sendTextPackage(
				authenticatedUsername(authentication),
				request.recipientUsername(),
				request.message());
		return PackageReceiptResponse.from(receipt);
	}

	@GetMapping("/{id}")
	public ReadPackageResponse read(
			@PathVariable Long id,
			Authentication authentication,
			@RequestHeader("X-Demo-Password") String recipientPassword) {
		SecurePackageService.ReadPackage readPackage = securePackageService.readTextPackage(
				id,
				authenticatedUsername(authentication),
				recipientPassword);
		return ReadPackageResponse.from(readPackage);
	}

	@GetMapping("/inbox/{username}")
	public List<PackageSummaryResponse> inbox(Authentication authentication, @PathVariable String username) {
		if (!authenticatedUsername(authentication).equals(username)) {
			throw new IllegalArgumentException("Authenticated user cannot read another user's inbox");
		}
		return securePackageService.inbox(username)
				.stream()
				.map(PackageSummaryResponse::from)
				.toList();
	}

	private String authenticatedUsername(Authentication authentication) {
		return authentication.getName();
	}

	public record SendPackageRequest(
			@NotBlank String recipientUsername,
			@NotBlank String message) {
	}

	public record PackageReceiptResponse(
			Long id,
			String senderUsername,
			String recipientUsername,
			Instant createdAt,
			String cryptoMode) {

		private static PackageReceiptResponse from(SecurePackageService.PackageReceipt receipt) {
			return new PackageReceiptResponse(
					receipt.id(),
					receipt.senderUsername(),
					receipt.recipientUsername(),
					receipt.createdAt(),
					receipt.cryptoMode());
		}
	}

	public record ReadPackageResponse(
			Long id,
			String senderUsername,
			String recipientUsername,
			String plaintextMessage,
			Instant createdAt,
			String cryptoMode) {

		private static ReadPackageResponse from(SecurePackageService.ReadPackage readPackage) {
			return new ReadPackageResponse(
					readPackage.id(),
					readPackage.senderUsername(),
					readPackage.recipientUsername(),
					readPackage.plaintextMessage(),
					readPackage.createdAt(),
					readPackage.cryptoMode());
		}
	}

	public record PackageSummaryResponse(
			Long id,
			String senderUsername,
			String recipientUsername,
			Instant createdAt) {

		private static PackageSummaryResponse from(SecurePackageService.PackageSummary summary) {
			return new PackageSummaryResponse(
					summary.id(),
					summary.senderUsername(),
					summary.recipientUsername(),
					summary.createdAt());
		}
	}
}
