package com.jwts.springjwt.service;

import com.jwts.springjwt.model.Role;
import com.jwts.springjwt.repository.UserRepository;
import com.jwts.springjwt.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final JwtTokenUtil jwtTokenUtil;


    public JwtUserDetailsService(UserRepository userRepository, JwtTokenUtil jwtTokenUtil) {
        this.userRepository = userRepository;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        com.jwts.springjwt.model.User user = userRepository.findByUserName(username);
        log.info(user.toString());
        return getUserAuthority(user.getRole().name(), user.getUserName(), user.getPassword());
    }

    public Map<String, Object> createUserDetails(final String firstName, final String lastName, final String userName, final String email, final String password) {
        final User getUserAuthority = getUserAuthority("ADMIN", userName, password);
        final String token = jwtTokenUtil.generateToken(getUserAuthority);
        final var user = getUser(firstName, lastName, email, password);

        userRepository.save(user);

        return getResponse(email, token);
    }

    private static Map<String, Object> getResponse(final String userName, final String token) {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("error", false);
        responseMap.put("username", userName);
        responseMap.put("message", "Account created successfully");
        responseMap.put("token", token);
        return responseMap;
    }

    private static User getUserAuthority(String userRole, String username, String password) {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(new SimpleGrantedAuthority(userRole));
        return new User(username, password, authorityList);
    }

    private com.jwts.springjwt.model.User getUser(String firstName, String lastName, String email, String password) {
        final String encodedPassword = new BCryptPasswordEncoder().encode(password);
        return com.jwts.springjwt.model.User.builder()
                .password(encodedPassword)
                .userName(email)
                .firstName(firstName)
                .lastName(lastName)
                .role(Role.ADMIN)
                .email(email)
                .build();
    }
}
