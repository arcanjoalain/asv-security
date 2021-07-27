package br.com.asv.security.ws;

import org.springframework.security.core.Authentication;

import br.com.asv.security.dto.IApplicationUser;

public abstract class ABaseSecurityController<E extends IApplicationUser<I>,I> {

	public abstract E findToLogin(E loginRequest);
	
	public abstract String prepareResult(String token, Authentication auth);

}
