package io.github.mleiman.authservice.security.mfa;

import io.github.mleiman.authservice.model.User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;

public class MfaAuthHandler implements AuthenticationSuccessHandler {
	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
	private final AuthenticationSuccessHandler mfaNotEnabledHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final String authority;

	public MfaAuthHandler(String successUrl, String authority) {
		SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler = new SimpleUrlAuthenticationSuccessHandler(successUrl);
		authenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		this.authority = authority;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		if (authentication instanceof UsernamePasswordAuthenticationToken) {
			var user = (User) authentication.getPrincipal();
			if (!user.isMfa()) {
				mfaNotEnabledHandler.onAuthenticationSuccess(request, response, authentication);
				return;
			}
		}
		saveAuthentication(request, response, new MfaAuthentication(authentication, authority));
		authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
	}

	private void saveAuthentication(HttpServletRequest request, HttpServletResponse response, MfaAuthentication mfaAuthentication) {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(mfaAuthentication);
		SecurityContextHolder.setContext(securityContext);
		securityContextRepository.saveContext(securityContext, request, response);
	}


}
