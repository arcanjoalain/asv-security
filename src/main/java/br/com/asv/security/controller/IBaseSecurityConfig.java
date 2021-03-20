package br.com.asv.security.controller;

import java.util.List;

import br.com.asv.security.dto.IApplicationUser;
import br.com.asv.security.filter.AJWTAuthenticationFilter;

public interface IBaseSecurityConfig< E extends IApplicationUser<I>,F extends AJWTAuthenticationFilter<E,I>,I> {
	
	 List<String> getPublicUrls();
	 
	 F createFilterAuth();
	 
}
