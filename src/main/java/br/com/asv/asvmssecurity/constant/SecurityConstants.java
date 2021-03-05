package br.com.asv.asvmssecurity.constant;


import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class SecurityConstants {
	private String secret = "SecretKeyToGenJWTs";
    private Long expirationTime = (long) 864_000_000; // 10 days
    private String TokenPrefix = "Bearer ";
    private String headerString = "Authorization";
    private String loginUrl = "/ws/login/**";
    
//	public long getExpirationTime() {
//		return EXPIRATION_TIME;
//	}
//	public String getSecret() {
//		return SECRET;
//	}
//	public String getTokenPrefix() {
//		return TOKEN_PREFIX;
//	}
//	public String getHeaderString() {
//		return HEADER_STRING;
//	}
//	public String getSignUpUrl() {
//		return SIGN_UP_URL;
//	}
}
