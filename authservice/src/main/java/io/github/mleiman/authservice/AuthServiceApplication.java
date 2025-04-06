package io.github.mleiman.authservice;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthServiceApplication {
	@Value("${ui.app.url}")
	private String uiAppUrl;

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

	@Bean
	public ApplicationRunner runner(RegisteredClientRepository registeredClientRepository) {
		return args -> {
			RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");
			if ( registeredClient == null) {
				registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("client")
						.clientSecret("sialababamak")
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
						.authorizationGrantTypes(types -> {
							types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
							types.add(AuthorizationGrantType.REFRESH_TOKEN);
						})
						.scopes(scopes -> {
							scopes.add(OidcScopes.OPENID);
							scopes.add(OidcScopes.PROFILE);
							scopes.add(OidcScopes.EMAIL);
						})
						.redirectUri(uiAppUrl)
						.postLogoutRedirectUri(uiAppUrl)
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.tokenSettings(TokenSettings.builder().refreshTokenTimeToLive(Duration.ofDays(90))
								.accessTokenTimeToLive(Duration.ofDays(1)).build())
						.build();
				registeredClientRepository.save(registeredClient);
			}
		};
	}
}
