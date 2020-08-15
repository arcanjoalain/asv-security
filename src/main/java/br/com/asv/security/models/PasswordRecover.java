package br.com.asv.security.models;

import java.util.Date;
import java.util.UUID;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.Type;

import lombok.Data;

@Entity
@Table(name = "password_recovery", schema = "security")
@DynamicUpdate
@DynamicInsert
@Data
public class PasswordRecover {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private		long		id;

	@Column(name = "user_id", nullable = false)
	private 	long		userID;

    @Column(name = "email", nullable = false)
    private 	String		email;

	@Column(name = "token", nullable = false)
	@Type(type = "org.hibernate.type.PostgresUUIDType")
    private		UUID		token;

    @Temporal(TemporalType.DATE)
    @Column(name = "until", nullable = false)
    private		Date		until;

}
