package br.com.asv.security.ws;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import br.com.asv.security.dto.IApplicationUser;


public abstract class ABaseSecuriyWs<
	A extends AuthService<E,I>,
	C extends ABaseSecurityController<E,I>, 
	E extends IApplicationUser<I>,I> {
	
	@Autowired
	private A authService;
	
	@Autowired
	private C controller;
	
	public abstract AuthenticationManager getAuthManager();
	
	
	@PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody E loginRequest) {
		IApplicationUser<I> result = controller.findToLogin(loginRequest);
		
		if(result!=null) {
			Authentication auth= authService.createAutheticate(getAuthManager(), loginRequest);
	        String token = authService.createToken(auth);
	        HttpHeaders httpHeaders = new HttpHeaders();
	        httpHeaders.set(authService.getSecurityConstants().getHeaderString(), token);
	        return new ResponseEntity<String>(controller.prepareResult(token, auth),httpHeaders,HttpStatus.OK);
		}else {
			return new ResponseEntity<>(HttpStatus.FORBIDDEN);
		}
		
    }

//    @PostMapping("/logout")
//    public ResponseEntity<Void> logout() {
// //       authService.removeToken();
//        return new ResponseEntity<>(HttpStatus.OK);
//    }
}
