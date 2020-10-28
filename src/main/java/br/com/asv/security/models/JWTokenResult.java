package br.com.asv.security.models;

import java.util.Date;

import lombok.Data;

@Data
public class JWTokenResult {

	private Date dateExpire;
	private String token;
}
