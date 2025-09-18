package com.haulmont.addon.oidc.web.security.oidc;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.haulmont.addon.oidc.service.OidcService;
import com.haulmont.cuba.core.global.UserSessionSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Component
public class OidcTokenCheckFilter extends OncePerRequestFilter {

    @Inject
    protected UserSessionSource userSessionSource;

    Gson gson = new GsonBuilder()
                .setLenient()
                .create();

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) 
            throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            try {
                String[] chunks = token.split("\\.");

                Base64.Decoder decoder = Base64.getUrlDecoder();

                String payload = new String(decoder.decode(chunks[1]));

                OidcService.OidcAccessData userData = gson.fromJson(payload, OidcService.OidcAccessData.class);
                final List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));

                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userData.getSub(),
                        null,
                            grantedAuthorities
                    );
                
                authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );
                
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                SecurityContextHolder.clearContext();
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        }
        
        filterChain.doFilter(request, response);
    }

}