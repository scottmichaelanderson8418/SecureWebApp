
package com.securewebapp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.securewebapp.auth.AuthenticationAccessHandler;
import com.securewebapp.auth.SecureUsersCredentialsService;
import com.securewebapp.dao.UserRepository;
import com.securewebapp.model.User;

@Configuration
@EnableWebSecurity
public class SecureAccessHandler {

	@Autowired
	private SecureUsersCredentialsService userSecureCredentialsService;

	// @Autowired - uses dependency injection to instantiate a class instance of
	// that interface
	@Autowired
	private UserRepository userRepository;

	public com.securewebapp.model.User findBy(String username) {
		return userRepository.findByUsername(username);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	public User createUser(final String userName, final String password,
			PasswordEncoder passwordEncoder) {
		User newUser = new User();
		newUser.setUsername(passwordEncoder.encode(userName));
		newUser.setPassword(passwordEncoder.encode(password));

		return newUser;

	}

	public com.securewebapp.model.User createUser(com.securewebapp.model.User newUser) {
		userSecureCredentialsService.registerUser(newUser);
		return newUser;
	}

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {

		// by customizing the "authorizeHttpRequest" we got rid of the default login we
		// had

		return httpSecurity.csrf(AbstractHttpConfigurer::disable)

				.authorizeHttpRequests(registry -> {
					registry.requestMatchers("/home", "/register/**", "/scottapi/**",
							"/getAllUsers").permitAll();
					registry.requestMatchers("/admin/**").hasRole("ADMIN");
					registry.requestMatchers("/user/**").hasRole("USER");

					registry.anyRequest().authenticated();

					//
				}).formLogin(httpSecurityFormLoginConfigurer -> {
					httpSecurityFormLoginConfigurer.loginPage("/login")
							.successHandler(new AuthenticationAccessHandler()).permitAll();
				}).build();

	}
}