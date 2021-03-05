package br.com.asv.security.ms.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.asv.security.ms.dto.IApplicationUser;

public abstract class ANewUserController<I> implements INewUserController<I>{
	
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public void signUp(IApplicationUser<I> user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        save(user);
    }

	
}
