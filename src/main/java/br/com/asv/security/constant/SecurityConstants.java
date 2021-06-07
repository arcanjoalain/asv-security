package br.com.asv.security.constant;


import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class SecurityConstants {
	private String secret = "SecretKeyToGenJWTs";
    private Long expirationTime = (long) 864_000_000; // 10 days
    private String tokenPrefix = "Bearer ";
    private String headerString = "Authorization";
    private String loginUrl = "/ws/login/**";
    
}
