package com.aditig.security.service;

import com.aditig.security.model.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


public class UserDetailsServiceImpl implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = findUserbyUsername(username);

        UserBuilder builder = null;
        if (user != null) {
            builder = org.springframework.security.core.userdetails.User.withUsername(username);
            builder.password(new BCryptPasswordEncoder().encode(user.getPassword()));
            builder.roles(user.getRoles());
        } else {
            throw new UsernameNotFoundException("User not found.");
        }

        return builder.build();
    }

    private User findUserbyUsername(String username) {
        // we are using dummy data here, you might need to load user data from database or other third party application
        if(username.equalsIgnoreCase("admin")) {
            return new User(username, "admin123", "ADMIN");
        } else if (username.equalsIgnoreCase("user")) {
            return new User(username, "user123", "USER");
        }
        return null;
    }
}