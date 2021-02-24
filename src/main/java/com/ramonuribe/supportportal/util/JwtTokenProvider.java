package com.ramonuribe.supportportal.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.ramonuribe.supportportal.domain.UserPrincipal;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static com.ramonuribe.supportportal.constant.SecurityConstant.*;
import static java.util.Arrays.stream;

@Component
public class JwtTokenProvider {

    // Value retrieved from application.yml file
    @Value("${jwt.secret}")
    private String secret;

    // Generate Token
    // This method will be called once a user is authenticated
    public String generateJwtToken(UserPrincipal userPrincipal) {
        // Getting claims using a helper method
        String[] claims = getClaimsFromUser(userPrincipal);
        // Creating JWT Tokens
        return JWT.create().withIssuer(SOME_COMPANY).withAudience(SOME_COMPANY_ADMINISTRATION)
                .withIssuedAt(new Date()).withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES, claims).withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(secret.getBytes()));
    }

    // Getting authorities from token
    // Used in (add class here)
    public List<GrantedAuthority> getAuthorities(String token) {
        // Creating helper method to get claims from token
        String[] claims = getClaimsFromToken(token);
        // map method below didn't give me any errors when I replaced with claim -> new SimpleGrantedAuthority(claim)
        // therefore that could mean what it was doing but have to test on repl (reminds me of js)
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    // With this Authentication, we'll be able to send it to the Spring Security Context
    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return usernamePasswordAuthenticationToken;
    }

    // Checking to see if token is valid
    public boolean isTokenValid(String username, String token) {
        JWTVerifier jwtVerifier = getJWTVerifier();
        // Using StringUtils (3rd party library) to verify username (String) is not empty
        // Also checking if token is not expired
        return StringUtils.isNotEmpty(username) && isTokenNotExpired(jwtVerifier, token);
    }

    // Getting Subject from Token
    public String getSubject(String token) {
        JWTVerifier jwtVerifier = getJWTVerifier();
        // returning Subject using verifier
        return jwtVerifier.verify(token).getSubject();
    }

    // HELPER METHODS


    // Helper method called in generateJwtToken to return an array of strings
    // containing authorities
    // Gets called in generateJWT
    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        List<String> authorities = new ArrayList<String>();
        for(GrantedAuthority grantedAuthority : userPrincipal.getAuthorities()) {
            authorities.add(grantedAuthority.getAuthority());
        }
        return authorities.toArray(new String[0]);
    }

    // Helper method to get claims from token
    // Gets called in getAuthorities
    private String[] getClaimsFromToken(String token) {
        // Method to get jwt verifier
        JWTVerifier verifier = getJWTVerifier();
        // getting claims after verifying token
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    // Method that builds our JWT Verifier using our secret and issuer
    // Gets called in getClaimsFromToken
    private JWTVerifier getJWTVerifier() {
        JWTVerifier jwtVerifier;
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            jwtVerifier = JWT.require(algorithm).withIssuer(SOME_COMPANY).build();
        } catch(JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }
        return jwtVerifier;
    }

    // Helper method to check if JWT Token is not expired
    // Gets called in isTokenValid
    private boolean isTokenNotExpired(JWTVerifier jwtVerifier, String token) {
        Date expiration = jwtVerifier.verify(token).getExpiresAt();
        // checks if token is after the current date (if true, token is not expired)
        return expiration.after(new Date());
    }
}
