package com.Tarun.CreditCardTracker.filter;

import java.io.IOException;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Tarun.CreditCardTracker.service.JwtService;
import com.Tarun.CreditCardTracker.service.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private final JwtService jwtService;
	private final ApplicationContext context;
	public JwtFilter(JwtService jwtService,ApplicationContext context) {
		this.jwtService=jwtService;
		this.context=context;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		String authHeader = request.getHeader("Authorization");
		String email = null;
		String token=null;
		
		if(request.getCookies()!=null) {
			for(Cookie cookie : request.getCookies()) {
				if(cookie.getName().equals("jwt")) {
					token = cookie.getValue();
					break;
				}
			}
		}
		
		if(token != null) {
			email = jwtService.extractEmail(token);
		}
		
		if(email != null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(email);
			if(jwtService.validateToken(token,userDetails)) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request, response);
		
	}

}
