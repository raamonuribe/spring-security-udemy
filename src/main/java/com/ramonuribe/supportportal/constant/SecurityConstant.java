package com.ramonuribe.supportportal.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 432_000_000; // 5 days (in milliseconds)
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified.";
    public static final String SOME_COMPANY = "Some Company, LLC"; // Issuer
    public static final String SOME_COMPANY_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to login to access this page.";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permissions to access this page.";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/api/v1/users/login", "/api/v1/users/register", "/api/v1/users/resetpassword/**", "/api/v1/users/image/**", "/h2-console/**"};
}
