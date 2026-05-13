package com.bankcore.shared.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
 * OncePerRequestFilter — garantiza que este filtro se ejecuta
 * exactamente UNA vez por request, sin importar cuántas veces
 * Spring lo llame internamente.
 *
 * @Component — Spring lo registra como bean y lo incluye
 * en la cadena de filtros automáticamente.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        /*
         * Extraemos el header Authorization de la request.
         * Formato esperado: "Bearer eyJhbGciOiJIUzI1NiJ9..."
         */
        final String authHeader = request.getHeader("Authorization");

        /*
         * Si no hay header o no empieza con "Bearer ",
         * dejamos pasar la request sin autenticar.
         * Spring Security decidirá después si el endpoint requiere auth o no.
         */
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        /*
         * Extraemos el token removiendo el prefijo "Bearer "
         * "Bearer " tiene 7 caracteres, substring(7) lo elimina.
         */
        final String token = authHeader.substring(7);
        final String email = jwtUtil.extractEmail(token);

        /*
         * Solo procesamos si:
         * 1. Pudimos extraer el email del token
         * 2. No hay una autenticación previa en el contexto de seguridad
         *
         * SecurityContextHolder guarda la autenticación del usuario actual
         * para este thread. Si ya está autenticado, no procesamos de nuevo.
         */
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            /*
             * Cargamos el usuario desde la BD para verificar que todavía existe
             * y obtener sus authorities (roles).
             */
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            /*
             * Validamos que el token sea válido para este usuario.
             * isTokenValid verifica firma y expiración.
             */
            if (jwtUtil.isTokenValid(token, userDetails.getUsername())) {

                /*
                 * Creamos el objeto de autenticación que Spring Security entiende.
                 * null en el segundo argumento porque con JWT no manejamos credenciales
                 * en este punto — ya las verificamos con el token.
                 */
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                /*
                 * Agregamos detalles de la request (IP, session) al objeto de auth.
                 */
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                /*
                 * Registramos la autenticación en el SecurityContext.
                 * A partir de aquí Spring Security sabe que este usuario
                 * está autenticado para el resto del procesamiento de esta request.
                 */
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        /*
         * Continuamos con el siguiente filtro en la cadena.
         * Si llegamos aquí sin autenticar, Spring Security
         * rechazará la request si el endpoint requiere autenticación.
         */
        filterChain.doFilter(request, response);
    }
}
