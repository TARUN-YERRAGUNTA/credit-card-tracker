package com.Tarun.CreditCardTracker.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.Tarun.CreditCardTracker.service.*;

@Controller
public class AuthController {
	
	private final AuthService authService;
	
	public AuthController(AuthService authService) {
		this.authService=authService;
	}
	
	@GetMapping("/login")
	public String getLogin() {
		return "auth/login";
	}
	
	@PostMapping("/login")
	public String postLogin(@RequestParam String email,@RequestParam String password,@RequestParam(required=false,name="rememberMe",defaultValue="false") boolean rememberMe,ModelMap map) {
		return authService.postLogin(email, password, rememberMe,map);
	}
	
	@GetMapping("/home")
	public String getHome() {
		return "pages/home";
	}
	
	@GetMapping("/signup")
	public String getSignup() {
		return "auth/signup";
	}
	
	@PostMapping("/signup")
	public String postSignUp(@RequestParam String firstName,@RequestParam String lastName,@RequestParam String email,@RequestParam String phone,@RequestParam String password,@RequestParam String confPassword,ModelMap map) {
		return authService.postSignup(firstName,lastName,email,phone,password,confPassword,map);
	}
	
	

}
