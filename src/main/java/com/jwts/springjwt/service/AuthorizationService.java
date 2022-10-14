package com.jwts.springjwt.service;

import com.jwts.springjwt.repository.UserRepository;
import com.jwts.springjwt.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class AuthorizationService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenUtil jwtTokenUtil;


    public AuthorizationService(AuthenticationManager authenticationManager, UserRepository userRepository, JwtTokenUtil jwtTokenUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public ResponseEntity<Map<String, Object>> authenticateUser(String username, String password) {
        try {
            return validateUserCredentials(username, password);
        } catch (BadCredentialsException e) {
            final Map<String, Object> errMessage = getResponseEntity(true, "Invalid Credentials", null);
            return ResponseEntity.status(401).body(errMessage);
        }
    }

    private ResponseEntity<Map<String, Object>> validateUserCredentials(String username, String password) {

        final Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        if (auth.isAuthenticated()) {

            log.info("Logged In");
            final UserDetails userDetails = loadUserByUsername(username);
            final String token = jwtTokenUtil.generateToken(userDetails);

            final Map<String, Object> responseMap = getResponseEntity(true, "Logged In", token);
            return ResponseEntity.status(200).body(responseMap);

        } else {

            final Map<String, Object> responseMap = getResponseEntity(true, "Invalid Credentials", null);
            return ResponseEntity.status(401).body(responseMap);
        }
    }

    private static Map<String, Object> getResponseEntity(final boolean err, final String message, final String token) {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("error", err);
        responseMap.put("message", message);
        responseMap.put("token", token);
        return responseMap;
    }

    private UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.jwts.springjwt.model.User user = userRepository.findByUserName(username);
        log.info(user.toString());
        return getUserAuthority(user.getRole().name(), user.getUserName(), user.getPassword());
    }

    private static User getUserAuthority(String userRole, String username, String password) {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(new SimpleGrantedAuthority(userRole));
        return new User(username, password, authorityList);
    }
}
