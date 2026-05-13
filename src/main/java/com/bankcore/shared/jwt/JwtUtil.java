package com.bankcore.shared.jwt;



import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*
 * @Component — le dice a Spring que esta clase es un bean.
 * Spring la instancia UNA sola vez al arrancar y la guarda en el contenedor IoC.
 * Cualquier clase que la necesite la recibe por inyección de dependencias.
 *
 * Es la diferencia con hacer "new JwtUtil()" — con @Component
 * existe una sola instancia compartida en toda la aplicación (Singleton).
 */
@Component
public class JwtUtil {

    /*
     * @Value("${app.jwt.secret}") — Spring lee este valor del application.yml
     * y lo inyecta automáticamente en este campo al crear el bean.
     *
     * Esto es otra forma de inyección de dependencias — no de objetos,
     * sino de valores de configuración. El código no sabe dónde vive
     * el secret, solo sabe que Spring se lo entregará.
     */
    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expiration}")
    private Long expiration;

    /*
     * Convierte el String secret en una clave criptográfica real.
     * Keys.hmacShaKeyFor() garantiza que la clave tenga el tamaño
     * mínimo requerido por HS256 (256 bits = 32 bytes).
     *
     * private porque es un detalle de implementación interno —
     * encapsulamiento en acción.
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /*
     * Genera un token JWT firmado con HS256.
     *
     * Un JWT tiene tres partes separadas por puntos:
     * HEADER.PAYLOAD.SIGNATURE
     *
     * Header: algoritmo usado (HS256)
     * Payload: claims — datos que viajan dentro del token (email, role)
     * Signature: HMAC del header+payload con el secret — garantiza integridad
     *
     * Si alguien modifica el payload, la firma no coincide y el token es inválido.
     */
    public String generateToken(String email, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);

        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    /*
     * Extrae el email (subject) del token.
     * Si el token está manipulado o expirado, JJWT lanza una excepción
     * antes de llegar al return — no hay forma de extraer datos de un token inválido.
     */
    public String extractEmail(String token) {
        return parseClaims(token).getSubject();
    }

    /*
     * Extrae el role del payload del token.
     */
    public String extractRole(String token) {
        return parseClaims(token).get("role", String.class);
    }

    /*
     * Valida que el token:
     * 1. Tenga firma válida (no fue manipulado)
     * 2. No esté expirado
     * 3. El subject coincida con el email del usuario
     *
     * El try-catch captura cualquier problema criptográfico o de expiración
     * y retorna false — nunca dejamos pasar un token dudoso.
     */
    public boolean isTokenValid(String token, String email) {
        try {
            String extractedEmail = extractEmail(token);
            return extractedEmail.equals(email) && !isTokenExpired(token);
        } catch (JwtException e) {
            return false;
        }
    }


    /*
     * Compara la fecha de expiración del token con el momento actual.
     */
    private boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    /*
     * Parsea y verifica la firma del token en un solo paso.
     * Si la firma no coincide con el secret, JJWT lanza ExpiredJwtException
     * o JwtException — nunca retorna claims de un token inválido.
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


}
