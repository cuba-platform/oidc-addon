package com.haulmont.addon.oidc.service;

import com.haulmont.cuba.security.entity.User;

public interface OidcRegistrationService {
    String NAME = "oidc_OidcRegistrationService";

    User findOrRegisterUser(OidcService.OidcAccessData userData);
}