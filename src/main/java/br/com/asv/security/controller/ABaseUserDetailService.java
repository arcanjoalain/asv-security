package br.com.asv.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.asv.security.dto.IApplicationUser;
import lombok.Getter;

public abstract class ABaseUserDetailService<I, U extends User> implements IBaseUserDetailService<I,U>{
	
	@Autowired
	@Getter
	private BCryptPasswordEncoder cryptPass;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		System.out.println("Load");
		IApplicationUser<I> applicationUser = findByUsername(username);
        if (applicationUser == null) {
            throw new UsernameNotFoundException(username);
        }
        return createUserResult(applicationUser);
        //return new User(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
    }
	
	
	@Override
	public String encriptPassword(IApplicationUser<I> user) {
		return getCryptPass().encode(user.getPassword());
    }
	
	@Override
	public String encriptPassword(String password) {
		return getCryptPass().encode(password);
    }
	

}
