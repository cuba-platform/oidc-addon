package com.haulmont.addon.oidc.web.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.haulmont.addon.oidc.service.OidcService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/v1/keycloak")
public class KeycloakController {

    @Inject
    protected OidcService keycloakService;

    private static final Logger logger = LoggerFactory.getLogger(KeycloakController.class);

    public static final String LOGOUT_TOKEN = "logout_token";

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        logger.info("Received backchannel logout request");

        String logoutToken = request.getParameter(LOGOUT_TOKEN);
        if (logoutToken == null) {
            logger.error("Missing 'logout_token' in request body");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Missing 'logout_token'");
        }

        logger.debug("Logout token: {}", logoutToken);

        DecodedJWT decode = JWT.decode(logoutToken);
        keycloakService.logout(decode.getSubject());

        logger.info("Successfully processed backchannel logout for token: {}", logoutToken);
        return ResponseEntity.ok("Logout processed");
    }
}