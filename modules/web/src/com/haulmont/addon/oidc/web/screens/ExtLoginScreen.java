/*
 * Copyright (c) 2008-2025 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.haulmont.addon.oidc.web.screens;

import com.haulmont.addon.oidc.service.OidcRegistrationService;
import com.haulmont.addon.oidc.service.OidcService;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.core.global.TimeSource;
import com.haulmont.cuba.gui.Notifications;
import com.haulmont.cuba.gui.components.Action;
import com.haulmont.cuba.gui.components.Image;
import com.haulmont.cuba.gui.executors.BackgroundWorker;
import com.haulmont.cuba.gui.executors.UIAccessor;
import com.haulmont.cuba.gui.screen.Subscribe;
import com.haulmont.cuba.gui.screen.UiController;
import com.haulmont.cuba.gui.screen.UiDescriptor;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.web.Connection;
import com.haulmont.cuba.web.app.login.LoginScreen;
import com.haulmont.cuba.web.controllers.ControllerUtils;
import com.haulmont.cuba.web.security.ExternalUserCredentials;
import com.vaadin.server.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.IOException;
import java.net.URI;
import java.util.Locale;


@UiController("ext-login")
@UiDescriptor("ext-login-screen.xml")
public class ExtLoginScreen extends LoginScreen {

    public static final String KEYCLOAK_REMEMBER_ME_EXP_COOKIE = "keycloak.rememberMe.exp";

    private static final Logger log = LoggerFactory.getLogger(ExtLoginScreen.class);

    private URI redirectUri;
    private UIAccessor uiAccessor;
    @Inject
    private OidcService keycloakService;
    @Inject
    private OidcRegistrationService keycloakRegistrationService;
    @Inject
    private GlobalConfig globalConfig;

    private final RequestHandler keycloakCallBackRequestHandler =
            this::handleKeycloakCallBackRequest;
    @Inject
    private BackgroundWorker backgroundWorker;
    @Inject
    private TimeSource timeSource;

    @Subscribe("submit")
    protected void onLoginButtonClick(Action.ActionPerformedEvent event) {
        login();

        if (connection.isAuthenticated()) {
            close(WINDOW_CLOSE_ACTION);
        }
    }

    @Override
    protected void onInit(InitEvent event) {
        super.onInit(event);
        this.uiAccessor = backgroundWorker.getUIAccessor();
    }

    @Subscribe("keycloakBtn")
    public void onKeycloakBtnClick(Image.ClickEvent event) {
        doKeycloakLogin();
    }

    @Subscribe
    public void onAfterInit(AfterInitEvent event) {
        if (!isExpiredRefreshToken()) {
            doKeycloakLogin();
        }
    }


    private boolean isExpiredRefreshToken() {
        String value = app.getCookieValue(KEYCLOAK_REMEMBER_ME_EXP_COOKIE);

        long currentTimeSecs = timeSource.currentTimeMillis() / 1000;
        return value == null || Long.parseLong(value) < currentTimeSecs;
    }

    private void doKeycloakLogin() {
        VaadinSession.getCurrent().addRequestHandler(keycloakCallBackRequestHandler);

        this.redirectUri = Page.getCurrent().getLocation();

        String loginUrl = keycloakService.getLoginUrl(globalConfig.getWebAppUrl(), OidcService.OAuth2ResponseType.CODE);
        Page.getCurrent().setLocation(loginUrl);
    }

    public boolean handleKeycloakCallBackRequest(VaadinSession session,
                                                 VaadinRequest request,
                                                 VaadinResponse response) throws IOException {
        if (request.getParameter("code") != null) {
            uiAccessor.accessSynchronously(() -> {
                try {
                    String code = request.getParameter("code");

                    OidcService.OidcToken oidcToken = keycloakService.getOidcToken(globalConfig.getWebAppUrl(), code);
                    log.info("Keycloak token: {}", oidcToken.getAccessToken());
                    OidcService.OidcAccessData userData = keycloakService.getAccessData(oidcToken);
                    OidcService.OidcRefreshData refreshData = keycloakService.getRefreshData(oidcToken);

                    Long exp = refreshData.getExp();
                    app.addCookie(KEYCLOAK_REMEMBER_ME_EXP_COOKIE, String.valueOf(exp));

                    User user = keycloakRegistrationService.findOrRegisterUser(userData);

                    Connection connection = app.getConnection();

                    Locale defaultLocale = messages.getTools().getDefaultLocale();
                    connection.login(new ExternalUserCredentials(user.getLogin(), defaultLocale));
                } catch (Exception e) {
                    log.error("Unable to login using Keycloak", e);
                    notifications.create()
                            .withCaption("Login error using Keycloak")
                            .withType(Notifications.NotificationType.ERROR)
                            .show();
                } finally {
                    session.removeRequestHandler(keycloakCallBackRequestHandler);
                }
            });

            ((VaadinServletResponse) response).getHttpServletResponse().
                    sendRedirect(ControllerUtils.getLocationWithoutParams(redirectUri));

            return true;
        }

        return false;
    }




}