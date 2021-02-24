package com.ramonuribe.supportportal.filter;

import static com.ramonuribe.supportportal.constant.SecurityConstant.*;
import com.ramonuribe.supportportal.util.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private JwtProvider jwtProvider;

    public JwtAuthorizationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Ensures that every OPTIONS request is able to go through without needing to be verified and returns a 200 status code
        if (request.getMethod().equalsIgnoreCase(OPTIONS_HTTP_METHOD)) {
            response.setStatus(HttpStatus.OK.value());
        } else {
            // Getting authorization header from request
            String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
            // Checking to see if authorization header is null or if it doesn't start with "Bearer " prefix
            if (authorizationHeader == null || !authorizationHeader.startsWith(TOKEN_PREFIX)) {
                filterChain.doFilter(request, response);
                return;
            }

            // Removing "Bearer " from the beginning of authorization header
            String token = authorizationHeader.substring(TOKEN_PREFIX.length());
            // Getting subject using method from JwtProvider
            String username = jwtProvider.getSubject(token);
            if (jwtProvider.isTokenValid(username, token)) {
                List<GrantedAuthority> authorities = jwtProvider.getAuthorities(token);
                Authentication authentication = jwtProvider.getAuthentication(username, authorities, request);
            }
        }
    }
}
