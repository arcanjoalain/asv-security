package br.com.asv.security.ws;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import com.auth0.jwt.JWT;

import br.com.asv.security.constant.SecurityConstants;
import br.com.asv.security.dto.IApplicationUser;
import lombok.Getter;

public abstract class AuthService<E extends IApplicationUser<I>,I> {
	
	

	@Getter
	private SecurityConstants securityConstants = new SecurityConstants();

	public String createToken(Authentication auth) {
		return JWT.create().withSubject(((User) auth.getPrincipal()).getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + securityConstants.getExpirationTime()))
				.sign(HMAC512(securityConstants.getSecret().getBytes(StandardCharsets.UTF_8)));
	}
	
	public String prepareValueHeader(String token) {
		return  token;
	}
	
	public Authentication createAutheticate(AuthenticationManager authenticationManager,
			E creds) {
	     return authenticationManager.authenticate(
                 new UsernamePasswordAuthenticationToken(
                         creds.getUsername(),
                         creds.getPassword(),
                         new ArrayList<>())
         );
            
	}
	
}
