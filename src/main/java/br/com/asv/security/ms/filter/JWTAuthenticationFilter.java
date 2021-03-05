package br.com.asv.security.ms.filter;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.asv.security.ms.dto.IApplicationUser;

public class JWTAuthenticationFilter<I>extends UsernamePasswordAuthenticationFilter {
	
	private SecurityConstants securityConstants  = new SecurityConstants();
	
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) 
                                                throws AuthenticationException {
        try {
            @SuppressWarnings("unchecked")
			IApplicationUser<I> creds = new ObjectMapper()
                    .readValue(req.getInputStream(), IApplicationUser.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUsername(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        @SuppressWarnings("unchecked")
		String token = JWT.create()
                .withSubject(((IApplicationUser<I>) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + securityConstants.getExpirationTime()))
                .sign(HMAC512(securityConstants.getSecret().getBytes()));
        res.addHeader(securityConstants.getHeaderString(), securityConstants.getTokenPrefix() + token);
    }
}
