package br.com.asv.security.controller;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.asv.security.dto.IApplicationUser;

public interface IBaseUserDetailService<I, U extends User> extends UserDetailsService{
	
	IApplicationUser<I> findByUsername(String username) throws UsernameNotFoundException;
	
	String encriptPassword(IApplicationUser<I> user) ;
	
	String encriptPassword(String password);
	
	BCryptPasswordEncoder getCryptPass();
	
	U createUserResult(IApplicationUser<I> applicationUser) throws UsernameNotFoundException;
}
