/*
 * Copyright 2023 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import java.util.function.Function;
import javax.security.auth.Subject;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserPrincipal;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

/**
 * Minimal {@link LoginService} used as the role delegate for {@link org.eclipse.jetty.security.SPNEGOLoginService}.
 * Role assignment is performed by Cruise Control wrappers after SPNEGO authentication.
 */
public class DummyRoleLoginService extends AbstractLifeCycle implements LoginService {

  private IdentityService _identityService = new DefaultIdentityService();

  @Override
  public String getName() {
    return "DummyRoleLoginService";
  }

  @Override
  public UserIdentity login(String username, Object credentials, Request request, Function<Boolean, Session> getSession) {
    Subject subject = new Subject();
    UserPrincipal principal = new UserPrincipal(username, SecurityUtils.NO_CREDENTIAL);
    principal.configureSubject(subject);
    subject.setReadOnly();
    return UserIdentity.from(subject, principal);
  }

  @Override
  public boolean validate(UserIdentity user) {
    return user != null;
  }

  @Override
  public IdentityService getIdentityService() {
    return _identityService;
  }

  @Override
  public void setIdentityService(IdentityService service) {
    _identityService = service;
  }

  @Override
  public void logout(UserIdentity user) {
  }
}
