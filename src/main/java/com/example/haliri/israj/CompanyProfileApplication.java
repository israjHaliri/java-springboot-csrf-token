package com.example.haliri.israj;

import com.example.haliri.israj.config.CorsInterceptor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
public class CompanyProfileApplication {

	public static void main(String[] args) {
		SpringApplication.run(CompanyProfileApplication.class, args);
	}

	@Bean
	public WebMvcConfigurerAdapter configureWebapp() {
		return new WebMvcConfigurerAdapter() {

			@Override
			public void addInterceptors(InterceptorRegistry registry) {
				registry.addInterceptor(new CorsInterceptor());
			}

		};
	}
}
