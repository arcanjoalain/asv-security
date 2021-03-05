package br.com.asv.security.ms.dto;

public interface IApplicationUser<I> {

	
	public long getId() ;

    public String getUsername();

    public void setUsername(String username) ;

    public String getPassword() ;

    public void setPassword(String password);
}
