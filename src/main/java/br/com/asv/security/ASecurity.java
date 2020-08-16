package br.com.asv.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import br.com.asv.security.authentication.IAuthenticationProvider;
import br.com.asv.security.authentication.JWTAuthorizationFilter;
import br.com.asv.security.bo.ISecurityBo;
import br.com.asv.security.bo.Password;
import br.com.asv.security.jwt.JWTokenService;

@Configuration
@EnableWebSecurity
public abstract class ASecurity extends WebSecurityConfigurerAdapter {
	
	 @Autowired
	    private ISecurityBo userDetailService;

    @Autowired
    private JWTokenService jwtUtil;

    @Autowired
    private IAuthenticationProvider authProvider;

    private static final String[] PUBLIC_MATCHERS = {
    		//"/*",
    		"/public/**",
            "/security/**",
            "/swagger-ui/**", 
            "/swagger-ui.html",
            "/v3/api-docs",
            "/v3/*",
            "/swagger-resources/**", 
            "/v2/api-docs",
            "/webjars/**"
    };

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().and().csrf().disable();
        http.authorizeRequests()
                .antMatchers(PUBLIC_MATCHERS).permitAll()
                .anyRequest().authenticated();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilter(new JWTAuthorizationFilter<>(authenticationManager(), jwtUtil, userDetailService));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        Password password = new Password();
        auth.userDetailsService(userDetailService).passwordEncoder(password.bCryptPasswordEncoder());
        auth.authenticationProvider(authProvider);
    }
}
