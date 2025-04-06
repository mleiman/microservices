package io.github.mleiman.authservice.exception;

public class ApiException extends RuntimeException {
    public ApiException(String message) {
        super(message);
    }
}
