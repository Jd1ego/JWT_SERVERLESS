package com.example.ApiBalala;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {
    private final String secretKey = "secreto";
    private final long validity = 3600000;

    public String generateToken(String username) {
        return Jwts.builder()
                .setHeaderParam("alg", "none")  // 🔹 Indica que no tiene firma
                .setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + validity))
                .compact();  // 🔹 No usa signWith()
    }





    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        return (bearerToken != null && bearerToken.startsWith("Bearer ")) ? bearerToken.substring(7) : null;
    }

    public boolean validateToken(String token) {
        try {
            System.out.println("Validando token: " + token);
            Claims claims = Jwts.parser().parseClaimsJwt(token).getBody();
            System.out.println("Expiración: " + claims.getExpiration());
            return claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("Error al validar token: " + e.getMessage());
            return false;
        }
    }


    public String getUsername(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody().getSubject();
    }

    public String getRole(String token) {
        return Jwts.parser().parseClaimsJwt(token).getBody().get("role", String.class);
    }

    public UsernamePasswordAuthenticationToken getAuthentication(String token, UserDetails userDetails) {
        String role = getRole(token);
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
        return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
    }
}
