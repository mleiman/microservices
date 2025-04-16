package io.github.mleiman.authservice.utils;

import jakarta.servlet.http.HttpServletRequest;

public class UserAgentUtils {
	public static final String HEADER_USER_AGENT = "User-Agent";
	public static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
	public static final String DEFAULT_VALUE = "unknown";

	public static String getIpAddress(HttpServletRequest request) {
		if (request == null) {
			return DEFAULT_VALUE;
		}
		String ipAddress = request.getHeader(HEADER_X_FORWARDED_FOR);
		if (ipAddress == null || ipAddress.isBlank()) {
			ipAddress = request.getRemoteAddr();
		}
		return ipAddress;
	}

	// TODO: use user agent analyzer
	public static String getClient(HttpServletRequest request) {
		return DEFAULT_VALUE;
	}

	public static String getDevice(HttpServletRequest request) {
		return DEFAULT_VALUE;
	}
}
