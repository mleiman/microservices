package io.github.mleiman.authservice.repo;

import io.github.mleiman.authservice.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

	User getUserByUuid(String uuid);

	User getUserByEmail(String email);

	@Modifying
	@Transactional
	@Query("UPDATE User u SET u.loginAttempts = 0 WHERE u.uuid = :uuid")
	int resetLoginAttemptsByUuid(String uuid);

	@Modifying
	@Transactional
	@Query("UPDATE User u SET u.loginAttempts = u.loginAttempts + 1 WHERE u.uuid = :uuid")
	void incrementLoginAttempts(String email);

	@Modifying
	@Transactional
	@Query("UPDATE User u SET u.lastLogin = CURRENT_TIMESTAMP WHERE u.uuid = :uuid")
	int updateLastLoginByUuid(String uuid);

	void insertLoginDevice(String uuid, String deviceName, String client, String ipAddress);
}
