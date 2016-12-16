/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.haliri.israj.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author israj
 */
public class CorsInterceptor extends HandlerInterceptorAdapter{

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String origin = request.getHeader("Origin");
        log.info("[REST]-[INTERCEPTOR] Value Origin {}", origin);

        response.addHeader("Access-Control-Allow-Origin", origin);
        if (request.getHeader("Access-Control-Request-Method") != null && "OPTIONS".equals(request.getMethod())) {
            log.info("Options Controller URI [{}] method [OPTIONS] headers [{}]",
                     new Object[]{request.getRequestURI(), request.getHeader("Origin")});
            response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.addHeader("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-XSRF-TOKEN");
            response.addHeader("Access-Control-Max-Age", "1");
        }
        return true;
    }

}
