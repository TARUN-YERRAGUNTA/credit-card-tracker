package com.Tarun.CreditCardTracker.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.Tarun.CreditCardTracker.model.Users;
import com.Tarun.CreditCardTracker.repository.UserRepository;

@Service
public class CustomOAuth2UserService implements OAuth2UserService{
	
	private final UserRepository userRepo;
	
	public CustomOAuth2UserService(UserRepository userRepo) {
		this.userRepo = userRepo;
	}

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// TODO Auto-generated method stub
		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);
		String email = oAuth2User.getAttribute("email");
		
		Users user = userRepo.findByEmail(email);
		
		if(user==null) {
			throw new OAuth2AuthenticationException("User not regester");
		}
		return oAuth2User;
		
		
		
	}

}
