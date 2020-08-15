package br.com.asv.security.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import br.com.asv.security.models.PasswordRecover;


public interface IPasswordRecoverRepository extends CrudRepository<PasswordRecover, Long> {

    PasswordRecover findByEmail(String email);
    PasswordRecover findByToken(UUID token);

    @Query(value = "DELETE FROM PasswordRecover pr WHERE pr.until BETWEEN current_date AND ?1")
    void trim(long timestamp);
}
