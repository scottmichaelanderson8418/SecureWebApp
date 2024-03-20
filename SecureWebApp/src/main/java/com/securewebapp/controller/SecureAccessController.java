
package com.securewebapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.securewebapp.model.User;
import com.securewebapp.service.SecureAccessHandler;

@Controller
public class SecureAccessController {

	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	private SecureAccessHandler handler;

	@GetMapping("/")
	public String getHomePage() {
		return "home";
	}

	@GetMapping("/secure")
	public String getSecurePage() {
		return "secure";
	}

	@GetMapping("/login")
	public String getLoginPage() {
		return "login";
	}

	@GetMapping("/register")
	public String getRegisterPage() {
		return "register";
	}

	@PostMapping("/register")
	public String createUser(@RequestParam("username") String username,
			@RequestParam("password") String password, Model model) {

		// check if this user is already registered
		User foundUser = handler.findBy(username);

		if (foundUser == null) {

			handler.createUser(username, password, passwordEncoder);

			return "login";
		} else {
			model.addAttribute("exists", true);
			return "register";
		}
	}
}
