package br.com.asv.security.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import br.com.asv.security.bo.ISecurityBo;
import br.com.asv.security.jwt.JWTokenService;
import br.com.asv.security.models.IEntitySecurity;

public class JWTAuthorizationFilter<E extends IEntitySecurity> extends BasicAuthenticationFilter {
	
	private JWTokenService jwtUtil;
	
	private ISecurityBo userDetailService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTokenService jwtUtil, ISecurityBo userDetailService) {
		super(authenticationManager);
		this.jwtUtil = jwtUtil;
		this.userDetailService = userDetailService;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		String header = request.getHeader("Authorization");
		System.out.println(header);
		if(header != null && header.startsWith("Bearer ")) {
			UsernamePasswordAuthenticationToken auth = getAuthentication(header.substring(7));
			if(auth != null) {
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		}
		else if(header != null && header.startsWith("Device ")) {
			SecurityContextHolder.getContext().setAuthentication(getAuthenticationForDevice(header.substring(8)));
		}
		chain.doFilter(request, response);
		
	}

	private UsernamePasswordAuthenticationToken getAuthentication(String token) {
		if (jwtUtil.tokenValido(token)) {
			String username = jwtUtil.getUsername(token);
			UserDetails user = userDetailService.loadUserByUsername(username);
			return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		}
		return null;
	}
	
	private UsernamePasswordAuthenticationToken getAuthenticationForDevice(String token) {
		return new UsernamePasswordAuthenticationToken(token, null, null);
	
	}
	

}
