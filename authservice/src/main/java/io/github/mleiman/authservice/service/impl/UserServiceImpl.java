package io.github.mleiman.authservice.service.impl;

import io.github.mleiman.authservice.model.User;
import io.github.mleiman.authservice.repo.UserRepository;
import io.github.mleiman.authservice.service.UserService;
import io.github.mleiman.authservice.utils.UserUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	@Override
	public User getUserByEmail(String email) {
		return userRepository.getUserByEmail(email);
	}

	@Override
	public void resetLoginAttempts(String uuid) {
		userRepository.resetLoginAttemptsByUuid(uuid);
	}

	@Override
	public void incrementLoginAttempts(String email) {
		userRepository.incrementLoginAttempts(email);
	}

	@Override
	public void setLastLogin(String uuid) {
		userRepository.updateLastLoginByUuid(uuid);
	}

	@Override
	public void addLoginDevice(String uuid, String deviceName, String client, String ipAddress) {
		userRepository.insertLoginDevice(uuid, deviceName, client, ipAddress);
	}

	@Override
	public boolean verifyCode(String uuid, String code) {
		User user = userRepository.getUserByUuid(uuid);
		return UserUtils.verifyCode(user.getQrCodeSecret(), code);
	}
}
