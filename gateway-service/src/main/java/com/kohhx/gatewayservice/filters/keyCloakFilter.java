package com.kohhx.gatewayservice.filters;

import com.kohhx.gatewayservice.DTO.InstrospectResponseDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class keyCloakFilter extends AbstractGatewayFilterFactory<keyCloakFilter.Config> {

    @Value("${spring.security.oauth2.client.provider.keycloak.instrospect-uri}")
    private String instrospectUrl;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-secret}")
    private String clientSecret;

    // Create a logger
    private static final Logger LOGGER = LoggerFactory.getLogger(keyCloakFilter.class);
    private final WebClient webClient;

    public keyCloakFilter(WebClient webClient) {
        super(Config.class);
        this.webClient = webClient;
    }

    public static class Config {
        // Put the configuration properties
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestUri = exchange.getRequest().getURI().getPath();
            LOGGER.info("Request to {} from {}", requestUri, exchange.getRequest().getRemoteAddress());

            if (checkIfURIisSecured(requestUri)) {
                String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

                if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                    throw new RuntimeException("Missing Authorization Header");
                }

                String token = authorizationHeader.substring(7);
                System.out.println("validationMono: Before");
                Mono<Boolean> validationMono = validate(token);
                System.out.println("validationMono: " + validationMono);
//                 Chain the validationMono with chain.filter
                return validationMono.flatMap(isActive -> {
                    if (isActive) {
                        LOGGER.info("Token is valid");
                        return chain.filter(exchange);
                    } else {
                        LOGGER.info("Token is invalid");
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
//                        return chain.filter(exchange);
                    }
                });
            } else {
                // If the URI is not secured, simply proceed with the filter chain
                return chain.filter(exchange);
            }
        };
    }


    private boolean checkIfURIisSecured(String requestURI) {
        List<String> notSecuredURI = List.of("/auth/token", "/auth/register", "/auth/validate");
        if (notSecuredURI.contains(requestURI)) {
            return false;
        }
        return true;
    }


    private Mono<Boolean> validate(String token) {

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("token", token);

        return webClient
                .post()
                .uri(instrospectUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(map) // Use bodyValue to provide the request body directly
                .retrieve()
                .bodyToMono(InstrospectResponseDTO.class)
                .map(InstrospectResponseDTO::getActive) // Assuming InstrospectResponseDTO has a getActive() method
                .onErrorResume(throwable -> {
                    LOGGER.error("Error during token introspection: " + throwable.getMessage());
                    // Return false or handle the error in an appropriate way
                    return Mono.just(false);
                });
    }

}
