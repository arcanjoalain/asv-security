package br.com.asv.security.repository;

import java.util.Optional;

//import org.springframework.data.repository.NoRepositoryBean;
//
//import br.com.asv.model.repositories.IBaseRepository;
import br.com.asv.security.models.IEntitySecurity;

//@NoRepositoryBean
public interface IEntitySecurityRepository<E extends IEntitySecurity<I>,I> 
//extends IBaseRepository<E,I>
{

//	Optional<E> findByIdOrderByProfileProfileRulesId(Long id);
	E findByUsername(String username);
//	IEntitySecurity findByInternal(Internal internal);
//    Optional<E> findByInternalPersonId(Long idPerson);
    Optional<E> findById(Long userID);
}
