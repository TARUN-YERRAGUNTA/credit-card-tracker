package com.Tarun.CreditCardTracker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.Tarun.CreditCardTracker.service.MyUserDetailsService;

@Configuration
public class SecurityConfig {
	
	private MyUserDetailsService myUserDetailsService;
	
	public SecurityConfig(MyUserDetailsService myUserDetailsService) {
		this.myUserDetailsService=myUserDetailsService;
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http
			.csrf(customizer->customizer.disable())
			.authorizeHttpRequests(auth -> auth.requestMatchers("/login","/signup","/forgotPassword").permitAll().anyRequest().authenticated())
			.authenticationProvider(authenticationProvider())
			.formLogin(form -> form.loginPage("/login").usernameParameter("email").defaultSuccessUrl("/home"));
		return http.build();	
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(myUserDetailsService);
		provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		return provider;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

}
