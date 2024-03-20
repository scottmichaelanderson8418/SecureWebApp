
package com.securewebapp.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.securewebapp.dao.UserRepository;
import com.securewebapp.model.User;

@Configuration
@EnableWebSecurity
public class SecureUsersCredentialsService implements UserDetailsService {
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
		// hi man man

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

	@Autowired
	private PasswordEncoder passwordEncoder;

	private List<SimpleGrantedAuthority> getAuthorities() {
		List<SimpleGrantedAuthority> authList = new ArrayList<>();
		authList.add(new SimpleGrantedAuthority("ROLE_USER"));
		return authList;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		User user = userRepository.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}

		// the get authorities method is a helper function that returns a list of
		// granted authorities
		return new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(), getAuthorities());
	}

	public UserDetails registerUser(User newUser) {
		newUser.setPassword(passwordEncoder.encode(newUser.getPassword()));
		User savedUser = userRepository.save(newUser);
		return new org.springframework.security.core.userdetails.User(savedUser.getUsername(),
				savedUser.getPassword(), getAuthorities());
	}

}