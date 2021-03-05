package br.com.asv.asvmssecurity.controller;

import java.util.LinkedList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import br.com.asv.asvmssecurity.constant.SecurityConstants;
import br.com.asv.asvmssecurity.dto.IApplicationUser;
import br.com.asv.asvmssecurity.filter.AJWTAuthenticationFilter;
import br.com.asv.asvmssecurity.filter.JWTAuthorizationFilter;
import lombok.Getter;

public abstract class ABaseSecurityConfig<
	E extends IApplicationUser<I>,
	F extends AJWTAuthenticationFilter<E,I>,I> 
		extends WebSecurityConfigurerAdapter implements IBaseSecurityConfig<E,F,I> {
    private IBaseUserDetailService<I> userDetailsService;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    
//    private F filterAuth;
//    private JWTAuthenticationFilter<I> filterAuth = new JWTAuthenticationFilter<I>(authenticationManager());
    
    @Getter
    private SecurityConstants securityConstants;

    public ABaseSecurityConfig(IBaseUserDetailService<I> userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        initialize();
    }
    
    public ABaseSecurityConfig(IBaseUserDetailService<I> userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder, String urlPublic) {
    	this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        initialize();
        this.securityConstants.setLoginUrl(urlPublic);
    }
    
    private void initialize() {
    	this.securityConstants = new SecurityConstants();
    }
    
    private RequestMatcher prepareRquestPublic() {
  	  List<RequestMatcher> publicUrl = new LinkedList<>();
  	  for (String urlPublic : getPublicUrls()) {
  		  publicUrl.add(new AntPathRequestMatcher(urlPublic));
  	 }
  	  return new OrRequestMatcher(publicUrl);
    }
    
    @Override
    public void configure(final WebSecurity web) {
      web.ignoring().requestMatchers(prepareRquestPublic());
      web.ignoring()
  	.antMatchers(HttpMethod.OPTIONS)
  	.antMatchers(HttpMethod.POST, "/auth/**")
  	.antMatchers(HttpMethod.GET, "/ws/file/**")
  	.antMatchers("/ws/translate/**")
  	.antMatchers("/assets/**", "/webjars/**", "/api-docs/**")
  	.antMatchers("/jsondoc/**", "/jsondoc-ui.html", "/swaggerui", "/swagger-ui.html", "/swagger-ui/*", "/swagger-resources/**", "/v2/api-docs");
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	F filterAuth = createFilterAuth();
    	filterAuth.setFilterProcessesUrl(this.securityConstants.getLoginUrl());
    	
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(this.securityConstants.getLoginUrl()).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(filterAuth)
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
    return source;
  }
}