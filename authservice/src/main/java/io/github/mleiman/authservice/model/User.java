package io.github.mleiman.authservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@AllArgsConstructor
@Getter
@Setter
public class User {

	// ? private Long id;
	@Id
	@Column(length = 36)
	private String uuid;
	private String email;
	private String password;
	private boolean mfa;
	private String qrCodeSecret;
	private String qrCodeImageUri;
	private String lastLogin;
	private Integer loginAttempts;

	private String role;
	private String authorities;

	private boolean accountLocked;
	private boolean accountEnabled;
	private boolean accountExpired;
	private boolean credentialsExpired;

	private Instant created;
	private Instant updated;



	public User() {
		this.uuid = UUID.randomUUID().toString();
	}
}
