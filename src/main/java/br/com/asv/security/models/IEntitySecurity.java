package br.com.asv.security.models;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

import br.com.asv.model.enums.StatusEntityEnum;


public interface IEntitySecurity<I> extends UserDetails {
	
	StatusEntityEnum getStatusEntity(); 
	
	I getPid();

	String getPasswordTemp();

	Date getDatePasswordTemp();

}
