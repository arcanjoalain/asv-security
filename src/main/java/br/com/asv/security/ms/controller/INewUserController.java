package br.com.asv.security.ms.controller;

import br.com.asv.security.ms.dto.IApplicationUser;

public interface INewUserController<I> {

	void save(IApplicationUser<I> user);
}
