package com.Tarun.CreditCardTracker.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import com.Tarun.CreditCardTracker.service.*;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletResponse;

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
	
	@GetMapping("/forgotPassword")
	public String getForgotPassword() {
		return "auth/forgotPassword";
	}
	
	@PostMapping("/generateOTP")
	public String postGenerateOTP(@RequestParam String email,ModelMap map) throws Exception {
		return authService.postGenerateOTP(email,map);
	}
	
	@PostMapping("/validateOTP")
	public String postValidateOTP(@RequestParam String otp1,@RequestParam String otp2,@RequestParam String otp3,@RequestParam String otp4,@RequestParam String otp5,@RequestParam String otp6,ModelMap map,@RequestParam String email) throws MessagingException {
		return authService.postValidateOTP(email,otp1,otp2,otp3,otp4,otp5,otp6,map);
	}
	
	@GetMapping("/resetPassword")
	public  String getResetPassword() {
		return "auth/resetPassword";
	}
	
	@PostMapping("/resetPassword")
	public String getResetPassword(@RequestParam String email,@RequestParam String password,@RequestParam String confirmPassword,ModelMap map) {
		return  authService.postResetPassword(email,password,confirmPassword,map);
	} 

}
