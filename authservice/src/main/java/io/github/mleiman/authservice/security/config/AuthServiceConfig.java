package io.github.mleiman.authservice.security.config;

import io.github.mleiman.authservice.security.ClientAuthenticationProvider;
import io.github.mleiman.authservice.security.ClientOAuth2RefreshTokenGenerator;
import io.github.mleiman.authservice.security.ClientRefreshTokenAuthenticationConverter;
import io.github.mleiman.authservice.security.UserJwtGenerator;
import io.github.mleiman.authservice.security.mfa.MfaAuthHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.HttpMethod.*;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthServiceConfig {

	private final JwtConfig jwtConfig;

	@Bean
	@Order(1)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository) throws Exception {
		http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()));
		OAuth2AuthorizationServerConfigurer authorizationConfigs = OAuth2AuthorizationServerConfigurer.authorizationServer()
				.tokenGenerator(tokenGenerator())
				.clientAuthentication(authentication -> {
					authentication.authenticationConverter(new ClientRefreshTokenAuthenticationConverter());
					authentication.authenticationProvider(new ClientAuthenticationProvider(registeredClientRepository));
				})
				.oidc(Customizer.withDefaults());

		http.securityMatcher(authorizationConfigs.getEndpointsMatcher())
				.with(authorizationConfigs, Customizer.withDefaults())
				.exceptionHandling(exceptions -> exceptions.accessDeniedPage("/access-denied")
						.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain secondarySecurityFilterChain(HttpSecurity http) throws Exception {
		http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()));
		http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.requestMatchers("/login").permitAll()
				.requestMatchers(POST, "/logout").permitAll()
				.requestMatchers("/mfa").hasAnyAuthority("MFA_REQUIRED")
				.anyRequest().authenticated());
		http.formLogin(login -> login.loginPage("/login")
				.successHandler(new MfaAuthHandler("/mfa", "MFA_REQUIRED"))
				.failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error")));
		http.logout(logout -> logout.logoutUrl("/logout")
				.logoutSuccessUrl("/")
				.addLogoutHandler(new CookieClearingLogoutHandler("JSESSIONID")));
		return http.build();
	}

	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new SavedRequestAwareAuthenticationSuccessHandler();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				//.issuer("http://localhost:8080")
				.build();
	}

	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		var jwtGenerator = UserJwtGenerator.init(new NimbusJwtEncoder(jwtConfig.jwkSource()));
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		OAuth2TokenGenerator<? extends OAuth2RefreshToken> refreshOAuth2TokenGenerator = new ClientOAuth2RefreshTokenGenerator();

		return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshOAuth2TokenGenerator);
	}

	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims(claims -> claims.put("authorities", getAuthorities(context)));
			}
		};
	}

	private String getAuthorities(JwtEncodingContext context) {
		return context.getPrincipal().getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		var corsConfiguration = new CorsConfiguration();
		corsConfiguration.setAllowCredentials(true);
		corsConfiguration.setAllowedOrigins(List.of(
				"http://localhost:3000", "http://localhost:4200"
				//"http://192.168.1.159:3000",
				//"100.14.214.212:3000",
				//"http://96.255.228.129:3000", "http://localhost:4200", "http://localhost:4200", "http://localhost:3000",
				//"http://securecapita.org", "http://192.168.1.216:3000", "http://securedoc.com"
		));
		corsConfiguration.setAllowedHeaders(Arrays.asList(ORIGIN, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, ACCEPT, AUTHORIZATION, "X_REQUESTED_WITH", ACCESS_CONTROL_REQUEST_METHOD, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_ALLOW_CREDENTIALS));
		corsConfiguration.setExposedHeaders(Arrays.asList(ORIGIN, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, ACCEPT, AUTHORIZATION, "X_REQUESTED_WITH", ACCESS_CONTROL_REQUEST_METHOD, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_ALLOW_CREDENTIALS));
		corsConfiguration.setAllowedMethods(Arrays.asList(GET.name(), POST.name(), PUT.name(), PATCH.name(), DELETE.name(), OPTIONS.name()));
		corsConfiguration.setMaxAge(3600L);
		var source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/", corsConfiguration);
		return source;
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new JdbcRegisteredClientRepository(jdbcTemplate);
	}
}
