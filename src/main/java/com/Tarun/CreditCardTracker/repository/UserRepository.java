package com.Tarun.CreditCardTracker.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Tarun.CreditCardTracker.model.Users;

public interface UserRepository extends JpaRepository<Users, String> {

	Users findByEmail(String email);
	
	Users findByPhone(String phn);
	
	Users save(Users user);
}
