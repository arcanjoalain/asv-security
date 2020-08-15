package br.com.asv.security.bo;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import br.com.asv.security.models.IEntitySecurity;
import br.com.asv.security.repository.IEntitySecurityRepository;
import lombok.Data;

@Data
public abstract class ASecurityBo<E extends IEntitySecurity> implements ISecurityBo {

	
	private IEntitySecurityRepository<E> iUserRepository;

//	@Autowired
//	private IPasswordRecoverRepository passwordRecoveryRepository;
//
//	private IEmailBO emailBO;
//
//	@Autowired
//	private PasswordEncoder passwordEncoder;
//
//	public SecurityBo(IEmailBO emailBO) {
//		this.emailBO = emailBO;
//	}
	
	public ASecurityBo() {
		
	}
	
	public ASecurityBo(IEntitySecurityRepository<E> iUserRepository) {
		this.iUserRepository = iUserRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return Optional.ofNullable(iUserRepository.findByUsername(username))
				.orElseThrow(() -> new UsernameNotFoundException("login.not.found"));
	}

	public E loadUserByUserID(Long userID) throws UsernameNotFoundException {
		return  (E) iUserRepository.findById(userID).orElseThrow(() -> new UsernameNotFoundException("user.not.found"));
	}

//	public boolean recoverPasswordByUsername(String username) {
//		IEntitySecurity user = iUserRepository.findByUsername(username);
//
//		if (user != null) {
//			PasswordRecover 		recover				= getPasswordRecoveryRepository().findByEmail(user.getEmail());
//			UUID					recoverID			= UUID.randomUUID();
//			Map<String, Object>		content				= new HashMap<>();
//
//			recover			= recover != null? recover : new PasswordRecover();
//
//			recover.setId(user.getId());
//			recover.setEmail(user.getEmail());
//			recover.setToken(recoverID);
//			recover.setUntil(Date.from(new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime().plusDays(1).atZone(ZoneId.systemDefault()).toInstant()));
//
//			content.put("name", user.getUsername());
//
//			try {
//				getPasswordRecoveryRepository().save(recover);
//				emailBO.sendRecoverPasswordEmail(recover.getEmail(), "noreply@itn.com.br", "Recuperar Senha", content);
//				return true;
//			} catch (Exception e) {
//				e.printStackTrace();
//				return false;
//			}
//		}
//		return false;
//	}

}
