package com.Tarun.CreditCardTracker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.Tarun.CreditCardTracker.filter.JwtFilter;
import com.Tarun.CreditCardTracker.service.CustomOAuth2UserService;
import com.Tarun.CreditCardTracker.service.MyUserDetailsService;
import com.Tarun.CreditCardTracker.service.OAuth2LoginSuccessHandler;

@Configuration
public class SecurityConfig {
	
	private final MyUserDetailsService myUserDetailsService;
	private final JwtFilter jwtFilter;
	private final CustomLogoutSuccessHandler customLogoutSuccessHandler;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
	private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

	
	public SecurityConfig(MyUserDetailsService myUserDetailsService,JwtFilter jwtFilter,CustomLogoutSuccessHandler customLogoutSuccessHandler,CustomOAuth2UserService customOAuth2UserService,OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler,CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler,CustomAuthenticationFailureHandler customAuthenticationFailureHandler) {
		this.myUserDetailsService=myUserDetailsService;
		this.jwtFilter=jwtFilter;
		this.customLogoutSuccessHandler=customLogoutSuccessHandler;
		this.customOAuth2UserService  = customOAuth2UserService;
		this.oAuth2LoginSuccessHandler=oAuth2LoginSuccessHandler;
		this.customAuthenticationSuccessHandler=customAuthenticationSuccessHandler;
		this.customAuthenticationFailureHandler=customAuthenticationFailureHandler;
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http
			.csrf(customizer->customizer.disable())
			.authorizeHttpRequests(auth -> auth.requestMatchers("/login","/signup","/forgotPassword","/generateOTP","/validateOTP","/resetPassword").permitAll().anyRequest().authenticated())
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
			.authenticationProvider(authenticationProvider())
			.logout(logout -> logout
				    .logoutUrl("/logout") // allow POST (default) and GET if you want
				    .invalidateHttpSession(true)
				    .clearAuthentication(true)
				    .deleteCookies("jwt","JSESSIONID")
				    .logoutSuccessHandler(customLogoutSuccessHandler)
				    .permitAll()
				)
			.formLogin(form -> form
					.loginPage("/login")
					.usernameParameter("email")
					.successHandler(customAuthenticationSuccessHandler)
					.failureHandler(customAuthenticationFailureHandler)
					.permitAll())
			.oauth2Login(oauth2 -> oauth2.loginPage("/login").userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService)).successHandler(oAuth2LoginSuccessHandler).failureHandler((request,response,exception)->{response.sendRedirect("/login?oAuthError=true");}))
			.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);		

		return http.build();	
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(myUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder());
		return provider;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
	
	@Bean 
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
