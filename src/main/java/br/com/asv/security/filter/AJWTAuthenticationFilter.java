package br.com.asv.security.filter;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import br.com.asv.security.constant.SecurityConstants;
import br.com.asv.security.dto.IApplicationUser;

public abstract class AJWTAuthenticationFilter<
		E extends IApplicationUser<I>,I> extends UsernamePasswordAuthenticationFilter {
	
	private SecurityConstants securityConstants  = new SecurityConstants();
	
    private AuthenticationManager authenticationManager;
    
    public AJWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    
    protected abstract Class<E> getClassUser();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
			E creds = (E) new ObjectMapper()
                    .readValue(req.getInputStream(), getClassUser());

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

        String token = JWT.create()
                .withSubject(( (User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + securityConstants.getExpirationTime()))
                .sign(HMAC512(securityConstants.getSecret().getBytes(StandardCharsets.UTF_8)));
        res.addHeader(securityConstants.getHeaderString(), securityConstants.getTokenPrefix() + token);
        String json = securityConstants.getHeaderString()+ securityConstants.getTokenPrefix() + token;
        res.getWriter().write(json);
    }
}