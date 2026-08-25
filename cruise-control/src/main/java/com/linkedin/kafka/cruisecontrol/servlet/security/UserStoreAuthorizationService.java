/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import org.eclipse.jetty.security.UserIdentity;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

/**
 * Can be used for authorization scenarios where a file can be created in a secure location with a relatively
 * low number of users. It follows the <code>username: password [,rolename ...]</code> format which corresponds to
 * the format used with {@link org.eclipse.jetty.security.HashLoginService}.
 */
public class UserStoreAuthorizationService extends AbstractLifeCycle implements CruiseControlAuthorizationService {

  private final UserStore _userStore;

  public UserStoreAuthorizationService(String privilegesFilePath) {
    this(userStoreFromFile(privilegesFilePath));
  }

  public UserStoreAuthorizationService(UserStore userStore) {
    _userStore = userStore;
  }

  @Override
  public UserIdentity getUserIdentity(String remoteAddr, String name) {
    return UserStoreIdentities.getUserIdentity(_userStore, name);
  }

  @Override
  protected void doStart() throws Exception {
    super.doStart();
    _userStore.start();
  }

  @Override
  protected void doStop() throws Exception {
    _userStore.stop();
    super.doStop();
  }

  private static UserStore userStoreFromFile(String privilegesFilePath) {
    CruiseControlPropertyUserStore userStore = new CruiseControlPropertyUserStore();
    userStore.setConfig(UserStoreIdentities.resourceFromPath(privilegesFilePath));
    return userStore;
  }
}
