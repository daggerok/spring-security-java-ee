package com.github.daggerok.springsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

// tag::content[]
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

//  final PasswordEncoder passwordEncoder;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
          .withUser("user1")
//            .password(passwordEncoder.encode("user1Pass"))
            .password("user1Pass")
            .roles("USER")
            .authorities("USER", "ROLE_USER")
        .and()
          .withUser("admin")
//            .password(passwordEncoder.encode("adminPass"))
            .password("adminPass")
            .roles("ADMIN")
            .authorities("ADMIN", "ROLE_ADMIN")
    ;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
//    MySavedRequestAwareAuthenticationSuccessHandler handler = new MySavedRequestAwareAuthenticationSuccessHandler();
    String[] paths = new String[] { "/", "/**", "/v1", "/v1**", "/v1/**" };
    http.csrf().disable()
        .logout().permitAll()
        .and().formLogin().permitAll()
        .and().servletApi()
//        .exceptionHandling()
        .and().headers()
                .xssProtection().xssProtectionEnabled(true)
                .and().cacheControl()
                .and().frameOptions().sameOrigin()
        .and().authorizeRequests()
          .antMatchers(GET, paths).permitAll()
          .antMatchers(POST, paths).hasAnyAuthority("ROLE_ADMIN")
          .antMatchers(POST, paths).hasAnyRole("ADMIN")
          .anyRequest().authenticated()
        .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
//          .anyRequest().authenticated()
////          .antMatchers("/**").fullyAuthenticated()
////          .antMatchers(POST).hasRole("ADMIN")
////          .antMatchers(POST).hasAnyAuthority("ADMIN", "ROLE_ADMIN")
////          .anyRequest()
////            .authenticated()
//          .and()
//        .formLogin()
//          .successHandler(handler)
//          .failureHandler(new SimpleUrlAuthenticationFailureHandler())
////          .defaultSuccessUrl("/", true)
////          .permitAll()
//          .and()
//        .logout()
//          .logoutUrl("/logout")
//          .logoutSuccessUrl("/")
//          .clearAuthentication(true)
//          .deleteCookies("JSESSIONID")
//          .invalidateHttpSession(false)
//          .permitAll()
//          .and()
////        .headers()
////          .frameOptions()
////            .sameOrigin()
////            .cacheControl()
////            .and()
////          .xssProtection()
////            .xssProtectionEnabled(true)
////            .and()
////          .and()
////          .csrf()
////            .disable()
////            //.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////            //.and()
//          .sessionManagement()
//          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//////        .and()
//////          .servletApi()
//////        .and()
//////          .rememberMe()
//////            .disable()
//////        .requestCache()
//////          .disable()
////        .and()
////          .httpBasic()
////            .disable()
    ;
  }

/*
  @Configuration
  public static class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
      return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
  }
*/
}
// end::content[]
