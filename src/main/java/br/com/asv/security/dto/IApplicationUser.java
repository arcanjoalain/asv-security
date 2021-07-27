package br.com.asv.security.dto;

public interface IApplicationUser<I> {
	
	I getPid() ;
	
	void setPid(I pid) ;

    String getUsername();

    void setUsername(String username) ;

    String getPassword() ;

    void setPassword(String password);
}
