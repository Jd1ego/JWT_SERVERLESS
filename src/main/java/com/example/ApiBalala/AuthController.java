package com.example.ApiBalala;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final UsuarioJPA usuarioJPA;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UsuarioJPA usuarioJPA, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.usuarioJPA = usuarioJPA;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public String register(@RequestBody UsuarioORM user) {
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("user"); // Rol por defecto
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        usuarioJPA.save(user);
        return "Usuario registrado con éxito";
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.username(), request.password()));
            return jwtUtil.generateToken(request.username());
        } catch (Exception e) {
            return "Error: Credenciales incorrectas";
        }
    }
}

// DTO para manejar la solicitud de login
record LoginRequest(String username, String password) {}
