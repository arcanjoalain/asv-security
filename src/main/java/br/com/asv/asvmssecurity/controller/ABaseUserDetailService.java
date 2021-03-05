package br.com.asv.asvmssecurity.controller;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.com.asv.asvmssecurity.dto.IApplicationUser;

import static java.util.Collections.emptyList;

public abstract class ABaseUserDetailService<I> implements IBaseUserDetailService<I>{

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		IApplicationUser<I> applicationUser = findByUsername(username);
        if (applicationUser == null) {
            throw new UsernameNotFoundException(username);
        }
        return new User(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
    }

}
