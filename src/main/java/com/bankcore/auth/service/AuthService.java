package com.bankcore.auth.service;


import com.bankcore.auth.dto.AuthResponse;
import com.bankcore.auth.dto.LoginRequest;
import com.bankcore.auth.dto.RegisterRequest;
import com.bankcore.shared.jwt.JwtUtil;
import com.bankcore.user.entity.User;
import com.bankcore.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/*
 * @Service — especialización de @Component para la capa de lógica de negocio.
 * Semánticamente le dice a cualquier desarrollador que lea el código:
 * "aquí vive la lógica de negocio, no infraestructura ni HTTP".
 *
 * @RequiredArgsConstructor — Lombok genera el constructor con todos los campos
 * marcados como "final". Spring detecta ese constructor y hace la inyección
 * de dependencias automáticamente. Es la forma más limpia de DI en Spring moderno.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    /*
     * INYECCIÓN DE DEPENDENCIAS — los tres colaboradores que AuthService necesita.
     * Son "final" porque nunca deben cambiar después de la construcción del objeto.
     * Spring los entrega por el constructor generado por @RequiredArgsConstructor.
     */
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    /*
     * @Transactional — garantiza que todo el método ocurra en una sola transacción.
     * Si algo falla en el medio (por ejemplo el save()), el INSERT se revierte.
     * La BD nunca queda en estado inconsistente.
     *
     * Regla: cualquier método que escriba en la BD lleva @Transactional.
     */
    @Transactional
    public AuthResponse register (RegisterRequest request) {

        /*
         * Validación de negocio — verificamos duplicados antes de intentar insertar.
         * Si dejáramos que MySQL lanzara el error de UNIQUE constraint, tendríamos
         * que capturar una excepción genérica de BD. Así el error es claro y controlado.
         */
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Ya existe un usuario con el email: " + request.getEmail());
        }

        /*
         * BCrypt hashea la password con un salt aleatorio.
         * El resultado es distinto cada vez aunque la password sea la misma.
         * Nunca se guarda la password en texto plano — jamás.
         *
         * BCrypt incluye el salt en el hash resultante, por eso
         * passwordEncoder.matches() puede verificar sin necesitar el salt por separado.
         */
        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(User.Role.ROLE_USER)
                .build();

        /*
         * Hibernate genera y ejecuta:
         * INSERT INTO users (email, full_name, password, role, created_at, active)
         * VALUES (?, ?, ?, ?, ?, ?)
         *
         * @PrePersist en User se ejecuta justo antes — setea createdAt y active=true.
         */
        userRepository.save(user);

        /*
         * Generamos el token inmediatamente después del registro.
         * El usuario queda autenticado sin necesidad de hacer login por separado.
         * UX más fluida y es el estándar en APIs modernas.
         */
        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        return AuthResponse.builder()
                .token(token)
                .email(user.getEmail())
                .fullName(user.getFullName())
                .role(user.getRole().name())
                .build();
    }

    /*
     * Login — verificamos credenciales y generamos token.
     * No lleva @Transactional porque solo lee de la BD, no escribe.
     */
    public AuthResponse login(LoginRequest request) {

        /*
         * Buscamos el usuario por email.
         * orElseThrow() lanza la excepción si Optional está vacío —
         * es la forma idiomática de manejar "no encontrado" con Optional.
         *
         * Usamos BadCredentialsException en vez de "usuario no encontrado"
         * por seguridad — no queremos revelar si el email existe o no.
         */
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));

        /*
         * BCrypt compara la password del request con el hash almacenado.
         * Internamente extrae el salt del hash y lo aplica a la password
         * del request para comparar. Nunca desencripta — BCrypt es unidireccional.
         */
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Credenciales inválidas");
        }

        /*
         * Verificamos que la cuenta esté activa.
         * Un admin podría desactivar una cuenta sin eliminarla — soft delete.
         */
        if (!user.getActive()) {
            throw new IllegalStateException("La cuenta está desactivada");
        }

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        return AuthResponse.builder()
                .token(token)
                .email(user.getEmail())
                .fullName(user.getFullName())
                .role(user.getRole().name())
                .build();
    }

}
