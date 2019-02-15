package com.github.daggerok.springsecurity;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
// tag::content[]
public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {

  public SecurityWebApplicationInitializer() {
    super(SpringSecurityConfig.class);
  }
}
// end::content[]
