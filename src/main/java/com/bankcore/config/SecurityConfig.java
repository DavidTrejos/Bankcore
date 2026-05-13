package com.bankcore.config;


import com.bankcore.shared.jwt.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.bankcore.user.repository.UserRepository;

/*
 * @Configuration — le dice a Spring que esta clase contiene definiciones de beans.
 * Es el reemplazo moderno del XML de configuración de Spring antiguo.
 * Cada método anotado con @Bean registra un objeto en el contenedor IoC.
 *
 * @EnableWebSecurity — activa el módulo de seguridad de Spring.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;
    private final JwtAuthFilter jwtAuthFilter;

    /*
     * @Bean — registra este método como productor de un bean en el contenedor IoC.
     * Cuando AuthService necesite un PasswordEncoder, Spring ejecuta este método
     * y le entrega el BCryptPasswordEncoder resultante.
     *
     * AQUÍ se resuelve el error "No beans of PasswordEncoder type found" —
     * este @Bean es exactamente lo que AuthService estaba esperando.
     *
     * BCrypt es el estándar de la industria para hashear passwords:
     * - Incluye salt aleatorio automáticamente
     * - Es intencionalmente lento (factor de costo configurable)
     * - Resistente a ataques de fuerza bruta y rainbow tables
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * UserDetailsService — interfaz de Spring Security para cargar usuarios.
     * Spring Security la usa internamente para verificar credenciales.
     *
     * Implementamos con lambda porque solo tiene un método — interfaz funcional.
     * Buscamos el usuario por email en nuestra BD y lo convertimos al formato
     * que Spring Security entiende.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> userRepository.findByEmail(email)
                .map(user -> org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .roles(user.getRole().name().replace("ROLE_", ""))
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + email));
    }

    /*
     * AuthenticationProvider — el componente que verifica credenciales.
     * DaoAuthenticationProvider usa UserDetailsService para cargar el usuario
     * y PasswordEncoder para verificar la password.
     *
     * Spring Security llama a este provider cuando alguien intenta autenticarse.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /*
     * AuthenticationManager — el orquestador de la autenticación.
     * Delega en los AuthenticationProviders registrados.
     * Lo exponemos como bean para poder inyectarlo donde lo necesitemos.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /*
     * SecurityFilterChain — el corazón de la configuración de seguridad.
     * Define qué endpoints son públicos, cuáles requieren autenticación,
     * y cómo se procesa cada request.
     *
     * Spring Security es una cadena de filtros — cada request pasa por
     * todos los filtros en orden antes de llegar al controller.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                /*
                 * Deshabilitamos CSRF porque usamos JWT, no cookies de sesión.
                 * CSRF protege contra ataques que explotan cookies — con JWT
                 * el token viaja en el header Authorization, no en cookies,
                 * así que CSRF no aplica.
                 */
                .csrf(AbstractHttpConfigurer::disable)

                /*
                 * Definimos qué endpoints son públicos y cuáles requieren token.
                 * requestMatchers → patrón de URL
                 * permitAll()     → no requiere autenticación
                 * anyRequest().authenticated() → todo lo demás requiere token válido
                 */
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )

                /*
                 * STATELESS — el servidor no guarda sesión en memoria.
                 * Cada request es independiente y debe traer su token.
                 * Esto hace la app horizontalmente escalable — cualquier
                 * instancia del servidor puede atender cualquier request.
                 */
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                /*
                 * Registramos nuestro AuthenticationProvider personalizado.
                 */
                .authenticationProvider(authenticationProvider())

                /*
                 * Insertamos nuestro JwtAuthFilter ANTES del filtro estándar
                 * de usuario/password de Spring Security.
                 * Así cada request primero pasa por nuestro filtro JWT.
                 */
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
