package com.Tarun.CreditCardTracker.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;

import com.Tarun.CreditCardTracker.model.Users;
import com.Tarun.CreditCardTracker.repository.UserRepository;

@Service
public class AuthService {
	
	private UserRepository userRepo;
	private AuthenticationManager authManager;
	
	public AuthService(AuthenticationManager authManager,UserRepository userRepo) {
		this.authManager=authManager;
		this.userRepo=userRepo;
	}

	public String postLogin( String email, String password,boolean rememberMe,ModelMap map) {

	    try {
	        Authentication authentication = authManager.authenticate(
	            new UsernamePasswordAuthenticationToken(email, password)
	        );

	        if(authentication.isAuthenticated()) {
	            return "pages/home";
	        }
	    } catch (AuthenticationException ex) {
	        // authentication failed
	        map.addAttribute("loginError", "Email and Password do not match");
	        return "auth/login";
	    }

	    // fallback (just in case)
	    map.addAttribute("loginError", "Login failed");
	    return "auth/login";
	}

	public String postSignup(String firstName, String lastName, String email, String phone, String password,
			String confPassword, ModelMap map) {
		// TODO Auto-generated method stub
		map.addAttribute("firstName",firstName);
		map.addAttribute("lastName",lastName);
		
		Users user = userRepo.findByEmail(email);
		
		
		if(user!=null) {
			map.addAttribute("validEmailError","Email already present!");
		}else {
			map.addAttribute("validEmail",email);
		}
		
		boolean validPhone = true;
		
		for(int i=0;i<phone.length();i++) {
			if(phone.charAt(i)<48 && phone.charAt(i)>58) {
				validPhone=false;
			}
		}
		
		if(phone.length()!=10 || !validPhone) {
			map.addAttribute("validPhoneError","Enter a valid phone number");
		}else {
			map.addAttribute("validPhone",phone);
		}
		
		boolean validPassword = password.equals(confPassword)?true:false;
		
		String validPasswordCriteria = passwordCriteria(password,confPassword);
		
		if(validPassword) {
			
			if(validPasswordCriteria.length()!=0) {
				map.addAttribute("validPasswordCriteriaError","Password does not met the criteria");
			}
		}else {
			map.addAttribute("validPasswordError","Passwords does not match");
		}
		
		if(user==null && validPhone && phone.length()==10 && validPassword && validPasswordCriteria.length()==0) {
			
			Users currUser = new Users();
			currUser.setFirstName(firstName);
			currUser.setLastName(lastName);
			currUser.setEmail(email);
			currUser.setPhn(phone);
			currUser.setPassword(password);
			
			userRepo.save(currUser);
			
			return "auth/login";
		}else {
			return "auth/signup";
		}
		
	}
	
	
	public String passwordCriteria(String password,String confPassword) {
		
		if(password.length()<8) {
			return "Password should contain at lease 8 characters";
		}
		
		int cap = 0;
		int normal = 0;
		int symbol = 0;
		int number =0;
		
		for(int i=0;i<password.length();i++) {
			int ascii = password.charAt(i);
			
			if(ascii>=33 && ascii<=47 || ascii>=58 && ascii<=64 || ascii>=91 && ascii<=96) {
				symbol++;
			}else if(ascii>=48 && ascii<=57) {
				number++;
			}else if(ascii>=65 && ascii<=90) {
				cap++;
			}else {
				normal++;
			}
		}
		
		if(cap ==0) {
			return "Password should contain a capital letter";
		}else if(symbol==0) {
			return "Password should contain a special character";
		}else if(number==0) {
			return "Password should contain a number";
		}else {
			return "";
		}
	}


}
