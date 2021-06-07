package br.com.asv.security.controller;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.asv.security.dto.IApplicationUser;

public interface IBaseUserDetailService<I> extends UserDetailsService{
	
	IApplicationUser<I> findByUsername(String username);
	
	String encriptPassword(IApplicationUser<I> user) ;
	
	BCryptPasswordEncoder getCryptPass();
}
