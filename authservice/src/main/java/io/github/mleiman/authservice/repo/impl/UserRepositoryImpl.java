package io.github.mleiman.authservice.repo.impl;

import io.github.mleiman.authservice.exception.ApiException;
import io.github.mleiman.authservice.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRepositoryImpl {
	private final JdbcClient jdbc;


	public User getUserByUuid(String uuid) {
		try {
			return jdbc.sql("SELECT_USER_BY_UUID_QUERY").param("uuid", uuid).query(User.class).single();
		} catch (EmptyResultDataAccessException e) {
			log.error(e.getMessage());
			throw new ApiException(String.format("No user found by UUID %s", uuid));
		} catch (Exception e) {
			log.error(e.getMessage());
			throw new ApiException("Error occured: " + e.getMessage());
		}
	}
}
