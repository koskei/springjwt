package com.jwts.springjwt.repository;

import com.jwts.springjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, String> {

    User findByUserName(String username);
}