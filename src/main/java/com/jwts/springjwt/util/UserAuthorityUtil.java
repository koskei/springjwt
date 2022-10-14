package com.jwts.springjwt.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.List;

public class UserAuthorityUtil {

    private static User getUserAuthority(final String userRole, final String username,final String password) {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(new SimpleGrantedAuthority(userRole));
        return new User(username, password, authorityList);
    }
}
