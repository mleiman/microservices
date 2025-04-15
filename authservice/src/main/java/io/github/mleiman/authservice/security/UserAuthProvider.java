package io.github.mleiman.authservice.security;

import io.github.mleiman.authservice.exception.ApiException;
import io.github.mleiman.authservice.model.User;
import io.github.mleiman.authservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.function.Consumer;

@Component
@RequiredArgsConstructor
public class UserAuthProvider implements AuthenticationProvider {
	private final UserService userService;
	private final BCryptPasswordEncoder passwordEncoder;

	private final Consumer<User> validateUser = user -> {
		if (user.isAccountLocked() || user.getLoginAttempts() >= 5) {
			throw new LockedException("User account is locked");
		}
		if (user.isCredentialsExpired()) {
			throw new CredentialsExpiredException("User credentials expired");
		}
		if (user.isAccountExpired()) {
			throw new DisabledException("User account is expired");
		}
		if (user.isAccountEnabled()) {
			throw new DisabledException("User account is disabled");
		}
	};

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			User user = userService.getUserByEmail((String) authentication.getPrincipal());
			if (user == null) {
				throw new ApiException("User not found");
			}
			validateUser.accept(user);

			if (!passwordEncoder.matches((String) authentication.getCredentials(), user.getPassword())) {
				throw new BadCredentialsException("Incorrect email/password combination");
			}
			String roleAndAuthority = user.getRole() + "," + user.getAuthorities();
			return UsernamePasswordAuthenticationToken.authenticated(user, "ASD - not our business",
					AuthorityUtils.commaSeparatedStringToAuthorityList(roleAndAuthority));
		} catch (ApiException | BadCredentialsException | LockedException | DisabledException |
				 CredentialsExpiredException e) {
			throw new ApiException(e.getMessage());
		} catch (Exception e) {
			throw new ApiException("Something went wrong");
		}
	}

	@Override
	public boolean supports(Class<?> authenticationType) {
		return authenticationType.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}
