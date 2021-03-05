package br.com.asv.asvmssecurity.controller;

import java.util.List;

import br.com.asv.asvmssecurity.dto.IApplicationUser;
import br.com.asv.asvmssecurity.filter.AJWTAuthenticationFilter;

public interface IBaseSecurityConfig< E extends IApplicationUser<I>,F extends AJWTAuthenticationFilter<E,I>,I> {
	
	 List<String> getPublicUrls();
	 
	 F createFilterAuth();
	 
}
