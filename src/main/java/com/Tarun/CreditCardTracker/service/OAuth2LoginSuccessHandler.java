package com.Tarun.CreditCardTracker.service;

import java.io.IOException;
import java.nio.file.attribute.UserDefinedFileAttributeView;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import com.Tarun.CreditCardTracker.model.Users;
import com.Tarun.CreditCardTracker.repository.UserRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Service
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private final UserRepository userRepo;
	private final JwtService jwtService;
	
	
	public  OAuth2LoginSuccessHandler(UserRepository userRepo,JwtService jwtService) {
		this.userRepo = userRepo;
		this.jwtService = jwtService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		// TODO Auto-generated method stub
		
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
		String email = oAuth2User.getAttribute("email");
		
		Users user = userRepo.findByEmail(email);
		
		if(user != null) {
			String token = jwtService.generateToken(email);
			Cookie cookie = new Cookie("jwt",token);
			cookie.setPath("/");
			cookie.setMaxAge(24*60*60);
			cookie.setHttpOnly(true);
			
			response.addCookie(cookie);
			response.sendRedirect("/creditCardTracker/home");
		}else {
			response.sendRedirect("/creditCardTracker/login?oAuthError=true");
		}
		
		
	}

}
