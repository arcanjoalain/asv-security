package br.com.asv.asvmssecurity.controller;

import org.springframework.security.core.userdetails.UserDetailsService;

import br.com.asv.asvmssecurity.dto.IApplicationUser;

public interface IBaseUserDetailService<I> extends UserDetailsService{

	
	IApplicationUser<I> findByUsername(String username);
}
