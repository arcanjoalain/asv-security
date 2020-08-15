package br.com.asv.security.models;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

import br.com.asv.model.entities.IBaseEntity;

public interface IEntitySecurity extends UserDetails,IBaseEntity {

	String getPasswordTemp();

	Date getDatePasswordTemp();

}
