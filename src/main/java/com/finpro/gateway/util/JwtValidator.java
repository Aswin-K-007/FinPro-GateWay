package com.finpro.gateway.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class JwtValidator {

    private JwtValidator() {
    }

    public static Mono<Void> validate(ServerWebExchange exchange,
                                      String jwtSecret,
                                      GatewayCallback callback) {

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            SecretKey key = Keys.hmacShaKeyFor(
                    jwtSecret.getBytes(StandardCharsets.UTF_8));

            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);

            return callback.proceed();

        } catch (ExpiredJwtException e) {
            return JwtResponse.sendError(exchange, HttpStatus.UNAUTHORIZED, "Token expired");

        } catch (UnsupportedJwtException e) {
            return JwtResponse.sendError(exchange, HttpStatus.UNAUTHORIZED, "Unsupported token");

        } catch (MalformedJwtException e) {
            return JwtResponse.sendError(exchange, HttpStatus.UNAUTHORIZED, "Malformed token");

        } catch (io.jsonwebtoken.security.SignatureException e) {
            return JwtResponse.sendError(exchange, HttpStatus.UNAUTHORIZED, "Invalid signature");

        } catch (JwtException e) {
            return JwtResponse.sendError(exchange, HttpStatus.UNAUTHORIZED, "Invalid token");
        }
    }

    @FunctionalInterface
    public interface GatewayCallback {
        Mono<Void> proceed();
    }
}