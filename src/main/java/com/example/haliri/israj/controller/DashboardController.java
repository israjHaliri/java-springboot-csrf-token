package com.example.haliri.israj.controller;

import com.sun.org.apache.regexp.internal.RE;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by israjhaliri on 25/10/16.
 */
@RestController
@RequestMapping("/api")
public class DashboardController {

    @RequestMapping(value = "/dashboard",method = RequestMethod.GET)
    public Map dashboard(){
        Map map = new HashMap<>();
        map.put("data","israj.halir@gmail.com");
        return map;
    }
}
