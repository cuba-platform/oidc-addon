# OIDC CUBA Addon

## Build from source

Build and install in local maven repo

```
./gradlew install -x checkstyleMain -x spotbugsMain
```

## Manual addon install

Select custom "Install addon manually" icon from CUBA Studio Addons dialog. Fill input with the full dependency artifact name:

```
com.haulmont.addon.oidc:oidc-addon-global:0.1-SNAPSHOT
```


## Configuration

Configure minimum required parameters to app.properties (core module):

```
oidc.clientId=my-client-id
oidc.realm=master
oidc.clientSecret=cJuxxxxxxxxxxxxxxxxxxxfY
oidc.baseUrl=http://172.17.0.1:8081
```

If you need to auto assign CUBA Roles to users authenticated with oidc provider add configuration parameter:

```
oidc.defaultRoles=system-full-access
```

## Usage

Create alternative login screens in web module:

ExtLoginScreen.java

```java
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
```
ext-login-screen.xml

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<window xmlns="http://schemas.haulmont.com/cuba/screen/window.xsd"
        caption="mainMsg://loginWindow.caption"
        messagesPack="com.company.demo.web.screens">
    <actions>
        <action id="submit"
                caption="mainMsg://loginWindow.okButton"
                icon="app/images/login-button.png"
                invoke="login" shortcut="ENTER"/>
    </actions>
    <layout stylename="c-login-main-layout" expand="loginWrapper">
        <vbox id="loginWrapper">
            <vbox id="loginMainBox"
                  align="MIDDLE_CENTER"
                  margin="true"
                  stylename="c-login-panel"
                  width="AUTO">
                <hbox id="loginTitleBox"
                      align="MIDDLE_CENTER"
                      spacing="true"
                      stylename="c-login-title">
                    <image id="logoImage"
                           align="MIDDLE_LEFT"
                           height="AUTO"
                           scaleMode="SCALE_DOWN"
                           stylename="c-login-icon"
                           width="AUTO"/>
                    <label id="welcomeLabel"
                           align="MIDDLE_LEFT"
                           stylename="c-login-caption"
                           value="mainMsg://loginWindow.welcomeLabel"/>
                </hbox>
                <capsLockIndicator id="capsLockIndicator"
                                   align="MIDDLE_CENTER"
                                   stylename="c-login-capslockindicator"/>
                <vbox id="loginForm"
                      spacing="true"
                      stylename="c-login-form">
                    <cssLayout id="loginCredentials"
                               stylename="c-login-credentials">
                        <textField id="loginField"
                                   htmlName="loginField"
                                   inputPrompt="mainMsg://loginWindow.loginPlaceholder"
                                   stylename="c-login-username"/>
                        <passwordField id="passwordField"
                                       autocomplete="true"
                                       htmlName="passwordField"
                                       inputPrompt="mainMsg://loginWindow.passwordPlaceholder"
                                       capsLockIndicator="capsLockIndicator"
                                       stylename="c-login-password"/>
                    </cssLayout>
                    <hbox id="rememberLocalesBox"
                          stylename="c-login-remember-locales">
                        <checkBox id="rememberMeCheckBox"
                                  caption="mainMsg://loginWindow.rememberMe"
                                  stylename="c-login-remember-me"/>
                        <lookupField id="localesSelect"
                                     nullOptionVisible="false"
                                     stylename="c-login-locale"
                                     textInputAllowed="false"/>
                    </hbox>
                    <button id="loginButton"
                            align="MIDDLE_CENTER"
                            action="submit"
                            stylename="c-login-submit-button"/>
                    <hbox align="MIDDLE_CENTER">
                        <image id="keycloakBtn"
                               width="30px"
                               scaleMode="CONTAIN">
                            <relativePath path="VAADIN/images/Keycloak_Logo.png"/>
                        </image>
                    </hbox>
                </vbox>
            </vbox>
        </vbox>
        <label id="poweredByLink"
               align="MIDDLE_CENTER"
               htmlEnabled="true"
               stylename="c-powered-by"
               value="mainMsg://cuba.poweredBy"/>
    </layout>
</window>
```

Place Keycloak_Logo.png into web module's web/VAADIN/images folder to provide button icon image

Add login screen override configuration to web-app.properties
```
cuba.web.loginScreenId=ext-login
```


## Authors

"Nikita Shchienko" <n.shchienko@haulmont.com>

"Aleksey Oblozhko" <a.oblozhko@haulmont.com>