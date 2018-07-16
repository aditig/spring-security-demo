package com.aditig.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    // authentication required but all users can access after login
    @GetMapping("/")
    public Boolean check() {
        return true;
    }

    // no authentication/login required, everyone can access
    @GetMapping("/security-none")
    public String notSecure() {
        return "Not secure";
    }

    // only users with ADMIN role can access
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "Admin";
    }
}
