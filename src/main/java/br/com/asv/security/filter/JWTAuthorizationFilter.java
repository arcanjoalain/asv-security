package br.com.asv.security.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.asv.security.constant.SecurityConstants;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private SecurityConstants securityConstants = new SecurityConstants();
	
    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(securityConstants.getHeaderString());

        if (header == null || !header.startsWith(securityConstants.getTokenPrefix())) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
    	UsernamePasswordAuthenticationToken result = null;
        String token = request.getHeader(securityConstants.getHeaderString());
        if (token != null) {
            // parse the token.
            String user = JWT.require(Algorithm.HMAC512(securityConstants.getSecret().getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .verify(token.replace(securityConstants.getTokenPrefix(), ""))
                    .getSubject();

            if (user != null) {
            	result =  new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
        }
        return result;
    }
}