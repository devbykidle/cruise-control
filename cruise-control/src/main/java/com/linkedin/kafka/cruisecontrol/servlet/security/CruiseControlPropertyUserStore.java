/*
 * Copyright 2020 LinkedIn Corp. Licensed under the BSD 2-Clause License (the "License"). See License in the project root for license information.
 */

package com.linkedin.kafka.cruisecontrol.servlet.security;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.eclipse.jetty.security.PropertyUserStore;
import org.eclipse.jetty.util.resource.Resource;

/**
 * {@link PropertyUserStore} that can enumerate known usernames (Jetty 12 removed
 * {@code getKnownUserIdentities()}).
 */
public class CruiseControlPropertyUserStore extends PropertyUserStore implements UserStoreIdentities.EnumerableUserStore {

  public CruiseControlPropertyUserStore() {
  }

  public CruiseControlPropertyUserStore(Resource config) {
    setConfig(config);
  }

  @Override
  public Set<String> knownUserNames() {
    return Collections.unmodifiableSet(new LinkedHashSet<>(_users.keySet()));
  }
}
