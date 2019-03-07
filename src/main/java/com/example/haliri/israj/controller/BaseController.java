package com.example.haliri.israj.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by israjhaliri on 25/10/16.
 */
@Controller
public class BaseController {

//    handle if cors config doesnt work use this, please make filter http servlet req that checking like this code
    @RequestMapping(value = "/api/base",method = RequestMethod.GET)
    @ResponseBody
    public Map dashboard(HttpServletRequest httpServletRequest){
        Map map = new HashMap<>();

        String host = httpServletRequest.getHeader("Host");
        if (!host.equals("localhost:8182")){
            map.put("data","israj");
            return map;
        }

        map.put("data","allowed");
        return map;
    }

    @CrossOrigin(origins = "http://localhost:9000")
    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public String login(){
       return "login";
    }
}
