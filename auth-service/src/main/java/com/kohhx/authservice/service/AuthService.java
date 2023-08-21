package com.kohhx.authservice.service;

import com.kohhx.authservice.DTO.InstrospectResponseDTO;
import com.kohhx.authservice.DTO.LoginRequestDTO;
import com.kohhx.authservice.DTO.LoginResponseDTO;
import com.kohhx.authservice.DTO.LogoutResponseDTO;
import com.kohhx.authservice.entity.UserCredential;
import com.kohhx.authservice.repository.UserCredentialRepository;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Service
public class AuthService {

    private final UserCredentialRepository userCredentialRepository;
    private final PasswordEncoder bCryptPasswordEncoder;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issueUrl;

    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUrl;

    @Value("${spring.security.oauth2.client.provider.keycloak.end-session-uri}")
    private String endSessionUrl;

    @Value("${spring.security.oauth2.client.provider.keycloak.instrospect-uri}")
    private String instrospectUrl;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.authorization-grant-type}")
    private String grantType;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Autowired
    public AuthService(UserCredentialRepository userCredentialRepository, PasswordEncoder bCryptPasswordEncoder, RestTemplate restTemplate) {
        this.userCredentialRepository = userCredentialRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.restTemplate = restTemplate;
    }

    public String saveUser (UserCredential userCredential) {
        String password = userCredential.getPassword();
        System.out.println("Username: " + userCredential.getUsername());
        userCredential.setPassword(bCryptPasswordEncoder.encode(userCredential.getPassword()));
        userCredentialRepository.save(userCredential);

        // Add to keycloak
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .clientId("admin-cli")
                .clientSecret(clientSecret)
                .username("admin") // Admin username
                .password("admin") // Admin password
                .build();

        RealmResource realmResource = keycloak.realm(realm);
        UsersResource usersResource = realmResource.users();

        UserRepresentation newUser = new UserRepresentation();
        newUser.setUsername(userCredential.getUsername());
        newUser.setFirstName("New");
        newUser.setLastName("User");
        newUser.setEmail("newuser@example.com");
        newUser.setEmailVerified(true);
        newUser.setEnabled(true);

        // Set the user's password
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue(password); // Set the desired password
        passwordCred.setTemporary(false); // Set to false for a permanent password
        newUser.setCredentials(Arrays.asList(passwordCred));
        usersResource.create(newUser);
        return "Added user successfully";
    }

    public LoginResponseDTO login(LoginRequestDTO loginRequestDTO) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("grant_type", grantType);
        map.add("username", loginRequestDTO.getUsername());
        map.add("password", loginRequestDTO.getPassword());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map,headers);

        ResponseEntity<LoginResponseDTO> response = restTemplate.postForEntity(tokenUrl, httpEntity, LoginResponseDTO.class);
        return response.getBody();
    }

    public LogoutResponseDTO logout(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map,headers);

        ResponseEntity<LogoutResponseDTO> response = restTemplate.postForEntity(endSessionUrl, httpEntity, LogoutResponseDTO.class);
        LogoutResponseDTO res = new LogoutResponseDTO();
        if(response.getStatusCode().is2xxSuccessful()) {
            res.setMessage("Logged out successfully");
        }

        return res;
    }

    public InstrospectResponseDTO validate(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("token", token);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map,headers);
        ResponseEntity<InstrospectResponseDTO> response = restTemplate.postForEntity(instrospectUrl, httpEntity, InstrospectResponseDTO.class);
        return response.getBody();
    }



}
