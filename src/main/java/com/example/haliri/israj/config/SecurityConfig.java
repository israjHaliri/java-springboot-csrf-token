package com.example.haliri.israj.config;

import com.allanditzel.springframework.security.web.csrf.CsrfTokenResponseHeaderBindingFilter;
import org.apache.log4j.Logger;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * Created by israjhaliri on 25/10/16.
 */
//    passsword  = $2a$10$M3p/awf2XC9Xiz4tdpge1eXbXb2nNwi1TA0pK7ntRWBHXBIYUrD3e

//@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final org.slf4j.Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("israj").password("026").roles("ADMIN");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .antMatchers("/**","/api/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll().loginPage("/login").permitAll()
                .successHandler(successHandler())
                .failureHandler(failureHandler())
//                .and()
//                .csrf().csrfTokenRepository(csrfTokenRepository())
                .and()
                .logout().logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                .and()
//                .addFilterAfter(new CsrfHeaderFilter(), CsrfFilter.class)
                .exceptionHandling().authenticationEntryPoint(new Http403ForbiddenEntryPoint());

    }

    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setHeaderName("X-XSRF-TOKEN");
        return repository;
    }


    class CsrfHeaderFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (csrf != null) {
                Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                String token = csrf.getToken();
                if (cookie==null || token!=null && !token.equals(cookie.getValue())) {
                    cookie = new Cookie("XSRF-TOKEN", token);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                }
            }
            filterChain.doFilter(request, response);
        }
    }


    private AuthenticationSuccessHandler successHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                httpServletResponse.getWriter().append("OK");
                httpServletResponse.setStatus(200);
            }
        };
    }

    private AuthenticationFailureHandler failureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                httpServletResponse.getWriter().append("Authentication failure");
                httpServletResponse.setStatus(401);
            }
        };
    }

    @Configuration
    public class RestConfig {
        @Bean
        public CorsFilter corsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowCredentials(true);
            config.addAllowedOrigin("3000");
            config.addAllowedHeader("*");
            config.addAllowedMethod("OPTIONS");
            config.addAllowedMethod("GET");
            config.addAllowedMethod("POST");
            config.addAllowedMethod("PUT");
            config.addAllowedMethod("DELETE");
            source.registerCorsConfiguration("/**", config);
            return new CorsFilter(source);
        }
    }
}
