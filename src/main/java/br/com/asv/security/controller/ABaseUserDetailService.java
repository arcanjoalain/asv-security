package br.com.asv.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.asv.security.dto.IApplicationUser;
import lombok.Getter;

import static java.util.Collections.emptyList;

public abstract class ABaseUserDetailService<I> implements IBaseUserDetailService<I>{
	
	@Autowired
	@Getter
	private BCryptPasswordEncoder cryptPass;

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		IApplicationUser<I> applicationUser = findByUsername(username);
        if (applicationUser == null) {
            throw new UsernameNotFoundException(username);
        }
        return new User(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
    }
	
	public String encriptPassword(IApplicationUser<I> user) {
		return getCryptPass().encode(user.getPassword());
    }
	
	public String encriptPassword(String password) {
		return getCryptPass().encode(password);
    }
	

}
