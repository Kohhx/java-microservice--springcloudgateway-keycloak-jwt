# Microservices with Spring Cloud Gateway, Keycloak, and Eureka Discovery Service

This project demonstrates the implementation of a microservices architecture using Spring Boot, Spring Cloud Gateway, Keycloak for authentication, and Eureka Discovery Service. It includes an Authentication service responsible for user registration, login, and JWT token generation using Keycloak. Users' data is stored in a PostgreSQL database. The Spring Cloud Gateway integrates with Keycloak for JWT authentication and directs authorized requests to the appropriate microservices, such as the Job microservice. Additionally, Eureka Discovery Service is used for service registration and discovery.

## Features

- **Authentication Service with Keycloak:**
  - User registration and login functionality using Keycloak.
  - User data storage in PostgreSQL database.
  - Generation of JWT tokens upon successful registration and login using Keycloak.

- **Spring Cloud Gateway:**
  - Acts as an API Gateway for routing and filtering requests.
  - Integrates with Keycloak for JWT authentication and validates tokens using Keycloak introspection endpoint.
  - Routes authenticated requests to the appropriate microservices.

- **Eureka Discovery Service:**
  - Facilitates service registration and discovery within the microservices architecture.
  - Provides a central registry for all microservices.

- **Job Service:**
  - Requires a valid JWT token for access.
  - Validates JWT tokens using Keycloak introspection endpoint before allowing access.
  - Provides functionality related to jobs (details to be specified).
