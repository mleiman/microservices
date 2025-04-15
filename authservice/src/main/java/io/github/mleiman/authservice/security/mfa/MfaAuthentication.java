package io.github.mleiman.authservice.security.mfa;

import lombok.Getter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

@Getter
public class MfaAuthentication extends AnonymousAuthenticationToken {
	private final Authentication primaryAuthentication;

	public MfaAuthentication(Authentication authentication, String authority) {
		super("anonymous", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS", authority));
		this.primaryAuthentication = authentication;
	}

	@Override
	public Object getPrincipal() {
		return this.primaryAuthentication.getPrincipal();
	}
}
