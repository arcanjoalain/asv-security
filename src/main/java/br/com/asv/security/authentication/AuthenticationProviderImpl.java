package br.com.asv.security.authentication;

import java.util.Collection;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import br.com.asv.security.bo.ASecurityBo;
import br.com.asv.security.exception.AuthorizationException;
import br.com.asv.security.jwt.JWTokenService;
import br.com.asv.security.models.IEntitySecurity;

@Component
public class AuthenticationProviderImpl<E extends IEntitySecurity<I>,I> implements IAuthenticationProvider {

	@Autowired
	private ASecurityBo<E,I> service;

	@Autowired
	private BCryptPasswordEncoder crypt;

	@Autowired
	private JWTokenService<I> jwtUtil;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException, AuthorizationException {
		return login(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

	@SuppressWarnings("unchecked")
	private Authentication login(Authentication authentication) {
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		IEntitySecurity<I> user =  (IEntitySecurity<I>) service.loadUserByUsername(username);
		
		if (user == null) {
			throw new UsernameNotFoundException("login.not.found");
		}

		if (!user.isEnabled()) {
			throw new AuthorizationException("user.disabled");
		}
		
		if (!crypt.matches(password, user.getPassword())) {
			if (!crypt.matches(password, user.getPasswordTemp())) {
				throw new BadCredentialsException("login.not.found");
			} else {
				long tempoSenha = (new Date()).getTime() - user.getDatePasswordTemp().getTime();
				if (tempoSenha > jwtUtil.getExpirationSenhaTemporaria()) {
					throw new CredentialsExpiredException("Senha temporária expirou");
				}
			}
		}

		return new UsernamePasswordAuthenticationToken(user, password, authorities);
	}

}
