package io.github.mleiman.authservice.service;

import io.github.mleiman.authservice.model.User;

public interface UserService {
	User getUserByEmail(String email);
	void resetLoginAttempts(String uuid);
	void incrementLoginAttempts(String email);
	void setLastLogin(String uuid);
	void addLoginDevice(String uuid, String deviceName, String client, String ipAddress);
	boolean verifyCode(String uuid, String code);
}
