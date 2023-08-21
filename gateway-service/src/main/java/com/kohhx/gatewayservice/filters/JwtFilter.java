package com.kohhx.gatewayservice.filters;

import com.kohhx.gatewayservice.services.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;

import java.util.List;

//@Component
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {
    // Create a logger
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtFilter.class);

    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) {
        super(Config.class);
        this.jwtService = jwtService;
    }

    public static class Config {
        // Put the configuration properties
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) -> {
            // Get the request URI
            String requestUri = exchange.getRequest().getURI().getPath();
            LOGGER.info("Request to {} from {}", requestUri, exchange.getRequest().getRemoteAddress());
            if (checkIfURIisSecured(requestUri)) {
                String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
                if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
//              throw new RuntimeException("Missing Authorization Header", 401, "Authorization header is missing");
                    throw new RuntimeException("Missing Authorization Header");
                }
                String token = authorizationHeader.substring(7);
                try {
                    jwtService.validateToken(token);
                } catch (Exception e) {
//                throw new RuntimeException("Invalid Token", 401, "Invalid Token");
                    throw new RuntimeException("Invalid Token");
                }
            }
            return chain.filter(exchange);
        };
    }

    private boolean checkIfURIisSecured(String requestURI) {
        List<String> notSecuredURI = List.of("/auth/token", "/auth/register", "/auth/validate");
        if (notSecuredURI.contains(requestURI)) {
            return false;
        }
        return true;
    }


}
