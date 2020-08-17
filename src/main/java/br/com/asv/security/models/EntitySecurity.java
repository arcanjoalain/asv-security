package br.com.asv.security.models;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.persistence.MappedSuperclass;

import org.springframework.security.core.GrantedAuthority;

import br.com.asv.model.entities.ABaseEntity;
import br.com.asv.model.enums.StatusEntityEnum;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
@MappedSuperclass
public abstract class EntitySecurity extends ABaseEntity implements IEntitySecurity{

	
	private static final long serialVersionUID = 1L;
	private String password;
	private String username;
	private Boolean enabled;
	private String PasswordTemp;
	private Date datePasswordTemp;
	private Boolean accountNonExpired;
	private Boolean credentialsNonExpired;
	
	@Override
	public boolean isAccountNonLocked() {
		return accountNonExpired;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return credentialsNonExpired;
	}

	@Override
	public boolean isAccountNonExpired() {
		return accountNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return getStatusEntity()==StatusEntityEnum.ENABLED;
	}
	
	@Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }


}
