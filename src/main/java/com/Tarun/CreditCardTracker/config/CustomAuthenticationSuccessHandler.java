package com.Tarun.CreditCardTracker.config;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.Tarun.CreditCardTracker.service.JwtService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final JwtService jwtService;

    public CustomAuthenticationSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
        setDefaultTargetUrl("/home");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        // Check if "Remember Me" was checked
        String rememberMe = request.getParameter("rememberMe");
        
        if (rememberMe != null) {
            // Generate JWT token
            String email = authentication.getName();
            String token = jwtService.generateToken(email);
            
            // Create cookie
            Cookie jwtCookie = new Cookie("jwt", token);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setSecure(false); // Set true in production with HTTPS
            jwtCookie.setPath("/creditCardTracker");
            jwtCookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
            
            response.addCookie(jwtCookie);
        }
        
        // Continue with the default behavior (redirect to /home)
        super.onAuthenticationSuccess(request, response, authentication);
    }
}