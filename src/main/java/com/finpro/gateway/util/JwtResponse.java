package com.finpro.gateway.util;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class JwtResponse {

    private JwtResponse() {
    }

    public static Mono<Void> sendError(ServerWebExchange exchange,
                                       HttpStatus status,
                                       String message) {

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders()
                .setContentType(MediaType.APPLICATION_JSON);

        String body = "{\"JWT Validation Eror\":\"" + message + "\"}";

        var buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
