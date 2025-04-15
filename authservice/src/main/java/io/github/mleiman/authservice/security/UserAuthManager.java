package io.github.mleiman.authservice.security;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class UserAuthManager {

	private final UserAuthProvider userAuthProvider;

	@Bean
	public AuthenticationManager authenticationManager() {
		return new ProviderManager(userAuthProvider);
	}
}
