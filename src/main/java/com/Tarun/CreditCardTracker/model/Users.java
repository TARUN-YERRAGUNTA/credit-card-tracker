package com.Tarun.CreditCardTracker.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Users {
	@Id
	private String email;
	@Column(nullable = false)
	private String firstName;
	private String lastName;
	@Column(nullable = false,length = 10)
	private String phn;
	@Column(nullable = false)
	private String password;

	
	public Users(){}
	
	
	
	public Users(String email, String firstName, String lastName, String phn, String password) {
		super();
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.phn = phn;
		this.password = password;
	}



	@Override
	public String toString() {
		return "users [email=" + email + ", firstName=" + firstName + ", lastName=" + lastName +", phn=" + phn + ", password=" + password + "]";
	}
	
	
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	
	public String getPhn() {
		return phn;
	}
	public void setPhn(String phn) {
		this.phn = phn;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
}
