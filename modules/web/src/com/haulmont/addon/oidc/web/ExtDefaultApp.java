package com.haulmont.addon.oidc.web;

import com.haulmont.addon.oidc.web.screens.ExtLoginScreen;
import com.haulmont.cuba.web.DefaultApp;

public class ExtDefaultApp extends DefaultApp {

    @Override
    protected void removeRememberMeTokens() {
        super.removeRememberMeTokens();

        this.removeCookie(ExtLoginScreen.KEYCLOAK_REMEMBER_ME_EXP_COOKIE);
    }
}
