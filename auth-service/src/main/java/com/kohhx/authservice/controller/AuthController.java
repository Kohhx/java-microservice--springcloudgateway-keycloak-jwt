package com.kohhx.authservice.controller;

import com.kohhx.authservice.DTO.InstrospectResponseDTO;
import com.kohhx.authservice.DTO.LoginRequestDTO;
import com.kohhx.authservice.DTO.LoginResponseDTO;
import com.kohhx.authservice.DTO.LogoutResponseDTO;
import com.kohhx.authservice.entity.UserCredential;
import com.kohhx.authservice.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;

    public AuthController(AuthService authService, AuthenticationManager authenticationManager) {
        this.authService = authService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public String addNewUser(@RequestBody UserCredential userCredential) {
        return authService.saveUser(userCredential);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> getToken(@RequestBody LoginRequestDTO loginRequestDTO){
        System.out.println("Login");
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequestDTO.getUsername(), loginRequestDTO.getPassword()));
        if (authenticate.isAuthenticated()) {
            LoginResponseDTO response  = authService.login(loginRequestDTO);
            return ResponseEntity.ok(response);
        } else {
            throw new RuntimeException("Authentication failed");
        }
    }

    @GetMapping("/logout")
    public ResponseEntity<LogoutResponseDTO> logout(@RequestParam("token") String token) {
       LogoutResponseDTO logoutResponseDTO =  authService.logout(token);
        return ResponseEntity.ok(logoutResponseDTO);
    }

    @GetMapping("/validate")
    public ResponseEntity<InstrospectResponseDTO> validate(@RequestParam("token") String token) {
        InstrospectResponseDTO instrospectResponseDTO =  authService.validate(token);
        return ResponseEntity.ok(instrospectResponseDTO);
    }

}
