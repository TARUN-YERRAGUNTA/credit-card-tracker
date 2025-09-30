package com.Tarun.CreditCardTracker.config;

import java.io.IOException;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        
        // Set custom error message based on exception type
        String errorMessage = "Login failed";
        
        if (exception instanceof BadCredentialsException) {
            errorMessage = "Email and Password do not match";
        }
        
        // Redirect to login page with error parameter
        setDefaultFailureUrl("/login?error=true");
        
        // Store error message in session so it can be displayed
        request.getSession().setAttribute("loginError", errorMessage);
        
        super.onAuthenticationFailure(request, response, exception);
    }
}