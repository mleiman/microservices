package io.github.mleiman.authservice.event;

import io.github.mleiman.authservice.model.User;
import io.github.mleiman.authservice.service.UserService;
import io.github.mleiman.authservice.utils.UserAgentUtils;
import io.github.mleiman.authservice.utils.UserUtils;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@AllArgsConstructor
public class ApiAuthEventListener {
	private final UserService userService;
	private final HttpServletRequest request;

	@EventListener
	public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
		log.info("Authentication success - {}", event);
		if (event.getAuthentication().getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
			User user = UserUtils.getUser(event.getAuthentication());
			userService.setLastLogin(user.getUuid());
			userService.resetLoginAttempts(user.getUuid());
			userService.addLoginDevice(user.getUuid(),
					UserAgentUtils.getDevice(request),
					UserAgentUtils.getClient(request),
					UserAgentUtils.getIpAddress(request));
		}
	}

	@EventListener
	public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
		log.info("Authentication failure - {}", event);
		if (event.getException() instanceof BadCredentialsException) {
			String email = (String) event.getAuthentication().getPrincipal();
			userService.incrementLoginAttempts(email);
		}
	}
}
