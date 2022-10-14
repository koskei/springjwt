package com.jwts.springjwt.controller;

import com.jwts.springjwt.service.AuthorizationService;
import com.jwts.springjwt.service.JwtUserDetailsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthenticationController {


    final JwtUserDetailsService userDetailsService;
    private final AuthorizationService authorizationService;

    public AuthenticationController(JwtUserDetailsService userDetailsService,
                                    AuthorizationService authorizationService)
    {
        this.userDetailsService = userDetailsService;
        this.authorizationService = authorizationService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> loginUser(@RequestParam("user_name") String username,
                                       @RequestParam("password") String password) {
        return authorizationService.getMapResponseEntity(username, password);
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> saveUser(@RequestParam("first_name") String firstName,
                                      @RequestParam("last_name") String lastName,
                                      @RequestParam("user_name") String userName, @RequestParam("email") String email
            , @RequestParam("password") String password) {

        Map<String, Object> responseMap = userDetailsService.createUserDetails(
                firstName, lastName,userName, email, password
        );
        return ResponseEntity.ok(responseMap);
    }
}
