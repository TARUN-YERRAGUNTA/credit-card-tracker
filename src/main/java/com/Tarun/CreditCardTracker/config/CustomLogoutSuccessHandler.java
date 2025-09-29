package com.Tarun.CreditCardTracker.config;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler{

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		
		HttpSession session   = request.getSession();
		if(session!=null) {
			session.invalidate();
		}
		
		Cookie[] cookies  = request.getCookies();
		if(cookies!=null) {
			for(Cookie cookie : cookies) {
				Cookie expiredCookie = new Cookie(cookie.getName(),null);
				expiredCookie.setMaxAge(0);
				expiredCookie.setPath("/");
				expiredCookie.setHttpOnly(true);
				response.addCookie(expiredCookie);
				
				
				Cookie expiredCookieRoot = new Cookie(cookie.getName(),null);
				expiredCookieRoot.setMaxAge(0);
				expiredCookieRoot.setPath("/CreditCardTracker");
				expiredCookieRoot.setHttpOnly(true);
				response.addCookie(expiredCookieRoot);
				
			}
		}
		
		Cookie jwtCookie = new Cookie("jwt", null);
        jwtCookie.setMaxAge(0);
        jwtCookie.setPath("/");
        jwtCookie.setHttpOnly(true);
        response.addCookie(jwtCookie);
        
        Cookie creditCardTrackerCookie = new Cookie("JSESSIONID", null);
        creditCardTrackerCookie.setMaxAge(0);
        creditCardTrackerCookie.setPath("/");
        response.addCookie(creditCardTrackerCookie);
        
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        
        
        String redirectUrl = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/login")
                .queryParam("logout", "true")
                .toUriString();
                
        response.sendRedirect(redirectUrl);
		
	}

}
