package org.zerhusen.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CorsFilter;
import org.zerhusen.security.jwt.JWTFilter;
import org.zerhusen.security.jwt.TokenProvider;

@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

   private final TokenProvider tokenProvider;
   private final CorsFilter corsFilter;

   public WebSecurityConfig(
      TokenProvider tokenProvider,
      CorsFilter corsFilter
   ) {
      this.tokenProvider = tokenProvider;
      this.corsFilter = corsFilter;
   }

   @Bean
   public RestTemplate getRestTemplate() {
      return new RestTemplate();
   }

   // Configure BCrypt password encoder =====================================================================
   @Bean
   public PasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
   }

   // Configure paths and requests that should be ignored by Spring Security ================================
   @Override
   public void configure(WebSecurity web) {
      web.ignoring()
         .antMatchers(HttpMethod.OPTIONS, "/**")

         // allow anonymous resource requests
         .antMatchers(
            "/",
            "/*.html",
            "/favicon.ico",
            "/**/*.html",
            "/**/*.css",
            "/**/*.js",
            "/h2-console/**"
         );
   }

   // Configure security settings ===========================================================================
   @Override
   protected void configure(HttpSecurity httpSecurity) throws Exception {
      JWTFilter customFilter = new JWTFilter(tokenProvider);

      httpSecurity
         .csrf().disable()
         .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
         .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)

         // enable h2-console
         .headers()
         .frameOptions()
         .sameOrigin()

         // create no session
         .and()
         .sessionManagement()
         .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

         .and()
         .authorizeRequests()
         .antMatchers("/api/authenticate").permitAll()

         .anyRequest().authenticated();
   }
}
