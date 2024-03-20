/**
 * 
 */
package com.securewebapp.dao;



import org.springframework.data.jpa.repository.JpaRepository;

import com.securewebapp.model.User;

/**
 * 
 */
public interface UserRepository extends JpaRepository<User, Long> {

	User findByUsername(String username);

}
