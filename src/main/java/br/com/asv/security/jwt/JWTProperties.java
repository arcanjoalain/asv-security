package br.com.asv.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@ConfigurationProperties(value = "jwt", prefix = "jwt")
@Data
public class JWTProperties {

	private 	String		headerPrefix;

	private		String		secret;

	private		String		appName;

	private 	String		header;

	private 	String		audience;

	private 	long		expiresIn;

	private 	long		expirationSenhaTemporaria;
}
