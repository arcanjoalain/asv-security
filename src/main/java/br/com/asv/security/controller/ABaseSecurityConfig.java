package br.com.asv.security.controller;

import java.util.LinkedList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import br.com.asv.security.constant.SecurityConstants;
import br.com.asv.security.dto.IApplicationUser;
import br.com.asv.security.filter.AJWTAuthenticationFilter;
import br.com.asv.security.filter.JWTAuthorizationFilter;
import lombok.Getter;

public abstract class ABaseSecurityConfig<U extends User, E extends IApplicationUser<I>, F extends AJWTAuthenticationFilter<E, I>, I>
		extends WebSecurityConfigurerAdapter implements IBaseSecurityConfig<E, F, I> {
	private IBaseUserDetailService<I, U> userDetailsService;
	private BCryptPasswordEncoder bCryptPasswordEncoder;

//    @Getter
//    private String urlPublic = "/auth/login/**";

	@Getter
	private SecurityConstants securityConstants;

	public ABaseSecurityConfig(IBaseUserDetailService<I, U> userDetailsService,
			BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		initialize();
//        this.securityConstants.setLoginUrl(this.urlPublic);
	}

	public ABaseSecurityConfig(IBaseUserDetailService<I, U> userDetailsService,
			BCryptPasswordEncoder bCryptPasswordEncoder, String urlPublic) {
		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
		initialize();
//        this.urlPublic = urlPublic;
		this.securityConstants.setLoginUrl(urlPublic);
	}

	private void initialize() {
		this.securityConstants = new SecurityConstants();
	}

	private RequestMatcher prepareRquestPublic() {
		List<RequestMatcher> publicUrl = new LinkedList<>();
		for (String urlPublicInt : getPublicUrls()) {
			publicUrl.add(new AntPathRequestMatcher(urlPublicInt));
		}
		return new OrRequestMatcher(publicUrl);
	}

	@Override
	public void configure(final WebSecurity web) {
		web.ignoring().requestMatchers(prepareRquestPublic());
//      web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**")
		web.ignoring().antMatchers(HttpMethod.OPTIONS)
				.antMatchers(HttpMethod.OPTIONS, this.securityConstants.getLoginUrl())
				.antMatchers(HttpMethod.POST, this.securityConstants.getLoginUrl())
				.antMatchers(HttpMethod.POST, "/auth/**").antMatchers(HttpMethod.GET, "/ws/file/**")
				.antMatchers("/ws/translate/**").antMatchers("/assets/**", "/webjars/**", "/api-docs/**")
				.antMatchers("/jsondoc/**", "/jsondoc-ui.html", "/swaggerui", "/swagger-ui.html", "/swagger-ui/*",
						"/swagger-resources/**", "/v2/api-docs");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		F filterAuth = createFilterAuth();
		filterAuth.setFilterProcessesUrl(this.securityConstants.getLoginUrl());

		http.cors().and().csrf().disable().authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll()
				.antMatchers(this.securityConstants.getLoginUrl()).permitAll().anyRequest().authenticated().and()
				.addFilter(filterAuth).addFilter(new JWTAuthorizationFilter(authenticationManager()))
				// this disables session creation on Spring Security
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}

//    @Bean
//    CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(*);
//        // configuration.setAllowedOriginPatterns(singletonList("*"));
//        configuration.setAllowedHeaders(singletonList("*"));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "DELETE", "PUT", "OPTIONS"));
//        configuration.setExposedHeaders(singletonList(this.securityConstants.getHeaderString()));
//        configuration.setAllowCredentials(false);
//        configuration.setMaxAge(3600L);
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }

//    @Bean
//	public CorsFilter corsFilter() {
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		CorsConfiguration config = new CorsConfiguration();
//		config.setAllowCredentials(true);
//		config.addAllowedOrigin("*");
//		config.addAllowedHeader("*");
//		config.addExposedHeader("Authorization");
//		config.addExposedHeader("X-Firebase-Auth");
//		config.addAllowedMethod("GET");
//		config.addAllowedMethod("POST");
//		config.addAllowedMethod("PUT");
//		config.addAllowedMethod("DELETE");
//		source.registerCorsConfiguration("/**", config);
//		return new CorsFilter(source);
//	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}