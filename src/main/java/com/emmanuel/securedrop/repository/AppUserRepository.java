package com.emmanuel.securedrop.repository;

import com.emmanuel.securedrop.domain.AppUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

	Optional<AppUser> findByUsername(String username);

	Optional<AppUser> findByEmail(String email);
}
