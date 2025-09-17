package com.Tarun.CreditCardTracker.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.Tarun.CreditCardTracker.model.UserPrincipal;
import com.Tarun.CreditCardTracker.model.Users;
import com.Tarun.CreditCardTracker.repository.UserRepository;

@Service
public class MyUserDetailsService implements UserDetailsService{
	
	private UserRepository userRepo;
	
	public MyUserDetailsService(UserRepository userRepo) {
		this.userRepo=userRepo;
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Users user = userRepo.findByEmail(email);
		if(user==null) {
			throw new UsernameNotFoundException("User not Present");
		}
		return new UserPrincipal(user);
	}

	

}
