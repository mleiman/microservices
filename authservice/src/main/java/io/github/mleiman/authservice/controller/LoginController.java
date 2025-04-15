package io.github.mleiman.authservice.controller;

import io.github.mleiman.authservice.model.User;
import io.github.mleiman.authservice.security.mfa.MfaAuthentication;
import io.github.mleiman.authservice.service.UserService;
import io.github.mleiman.authservice.utils.UserUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@AllArgsConstructor
public class LoginController {
	private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final AuthenticationFailureHandler authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler("/mfa?error");
	private final UserService userService;

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/mfa")
	public String mfa(Model model, @CurrentSecurityContext SecurityContext context) {
		model.addAttribute("email", getAuthenticatedUser(context.getAuthentication()));
		return "mfa";
	}

	@PostMapping("/mfa")
	public void validateCode(@RequestParam("code") String code, HttpServletRequest request, HttpServletResponse response,
							 @CurrentSecurityContext SecurityContext context) throws ServletException, IOException {
		User user = UserUtils.getUser(context.getAuthentication());
		if (!userService.verifyCode(user.getUuid(), code)) {
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("Invalid QR code."));
			return;
		}
		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, getAuthentication(request, response));
	}

	private Authentication getAuthentication(HttpServletRequest request, HttpServletResponse response) {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		MfaAuthentication mfaAuthentication = (MfaAuthentication) securityContext.getAuthentication();
		securityContext.setAuthentication(mfaAuthentication);
		SecurityContextHolder.setContext(securityContext);
		securityContextRepository.saveContext(securityContext, request, response);
		return mfaAuthentication.getPrimaryAuthentication();
	}

	private Object getAuthenticatedUser(Authentication authentication) {
		return ((User) authentication.getPrincipal()).getEmail();
	}
}
