package com.emmanuel.securedrop.repository;

import com.emmanuel.securedrop.domain.AppUser;
import com.emmanuel.securedrop.domain.SecurePackage;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurePackageRepository extends JpaRepository<SecurePackage, Long> {

	List<SecurePackage> findByRecipient(AppUser recipient);

	List<SecurePackage> findBySender(AppUser sender);
}
