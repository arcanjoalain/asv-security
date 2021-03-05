package br.com.asv.security.ms.constant;

import org.springframework.stereotype.Component;

@Component
public class SecurityConstants {
	private static final String SECRET = "SecretKeyToGenJWTs";
    private static final long EXPIRATION_TIME = 864_000_000; // 10 days
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_STRING = "Authorization";
    private static final String SIGN_UP_URL = "/auth/**";
    
	public long getExpirationTime() {
		return EXPIRATION_TIME;
	}
	public String getSecret() {
		return SECRET;
	}
	public String getTokenPrefix() {
		return TOKEN_PREFIX;
	}
	public String getHeaderString() {
		return HEADER_STRING;
	}
	public String getSignUpUrl() {
		return SIGN_UP_URL;
	}
}
