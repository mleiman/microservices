package io.github.mleiman.authservice.security;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

@Component
public class ClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {
	@Override
	public Authentication convert(HttpServletRequest request) {
		var grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equalsIgnoreCase(grantType)) {
			return null;
		}

		var clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
		if (StringUtils.isBlank(clientId)) {
			return null;
		}

		return new ClientRefreshTokenAuthentication(clientId);

	}
}
