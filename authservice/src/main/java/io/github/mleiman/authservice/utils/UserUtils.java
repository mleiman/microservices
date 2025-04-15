package io.github.mleiman.authservice.utils;

import io.github.mleiman.authservice.model.User;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

public class UserUtils {
	public static User getUser(Authentication authentication) {
		if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken) {
			var usernamePasswordAuthToken = (UsernamePasswordAuthenticationToken) authentication.getPrincipal();
			return (User) usernamePasswordAuthToken.getPrincipal();
		}
		return (User) authentication.getPrincipal();
	}

	public static boolean verifyCode(String secret, String code) {
		// TODO: implement
		return StringUtils.equals(secret, code);
	}
}
