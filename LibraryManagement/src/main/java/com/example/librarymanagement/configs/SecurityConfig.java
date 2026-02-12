package com.example.librarymanagement.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@Order(1) // Ensures this config is applied first
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Make sure these are strictly permitted
                        .requestMatchers("/", "/register", "/login", "/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()

                        // Explicitly protect the Admin routes
                        .requestMatchers("/dashboard/**").hasRole("ADMIN")
                        .requestMatchers("/admin/**", "/authors/**", "/books/**", "/users/**", "/lendings/**").hasRole("ADMIN")

                        // Explicitly protect User routes
                        .requestMatchers("/user/**").hasRole("USER")

                        // Everything else requires authentication
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/") // Tells Spring your login form is on the home page
                        .loginProcessingUrl("/login") // Matches the th:action in your modal form
                        .successHandler(customSuccessHandler())
                        .failureUrl("/?error=true") // Redirects back to home with an error flag if login fails
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/?logout")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return (request, response, authentication) -> {
            var roles = authentication.getAuthorities();

            // Logged in Admins go to /dashboard (your index.html logic)
            if (roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                response.sendRedirect("/dashboard");
            }
            // Logged in Users go to their specific dashboard
            else if (roles.stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER"))) {
                response.sendRedirect("/user/dashboard");
            }
            // If something goes wrong, go to home
            else {
                response.sendRedirect("/");
            }
        };
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}