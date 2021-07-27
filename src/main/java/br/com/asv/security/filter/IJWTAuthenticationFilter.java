package br.com.asv.security.filter;

import org.springframework.security.core.Authentication;

public interface IJWTAuthenticationFilter {

	String prepareResult(String token, Authentication auth);
}
