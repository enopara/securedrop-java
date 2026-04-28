package com.emmanuel.securedrop.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "secure_packages")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SecurePackage {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "sender_id", nullable = false)
	private AppUser sender;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "recipient_id", nullable = false)
	private AppUser recipient;

	@Column(nullable = false, length = 255)
	private String originalFileName;

	@Column(nullable = false, length = 512)
	private String storedFilePath;

	@Column(nullable = false, columnDefinition = "TEXT")
	private String encryptedFileKey;

	@Column(nullable = false, length = 64)
	private String fileSha256;

	@Column(nullable = false, updatable = false)
	private Instant createdAt = Instant.now();
}
