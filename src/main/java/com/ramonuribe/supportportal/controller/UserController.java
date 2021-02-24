package com.ramonuribe.supportportal.controller;

import com.ramonuribe.supportportal.domain.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @GetMapping("/home")
    public String testString() {
        return "Endpoint is working.";
    }
}
