package br.com.asv.asvmssecurity.dto;

public interface IApplicationUser<I> {
	
	public I getPid() ;

    public String getUsername();

    public void setUsername(String username) ;

    public String getPassword() ;

    public void setPassword(String password);
}
