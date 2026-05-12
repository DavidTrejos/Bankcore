package com.bankcore.user.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {


    /*
     * @Id marca este campo como clave primaria.
     * @GeneratedValue con IDENTITY delega el auto-incremento a MySQL.
     * Usamos Long (no int) para soportar miles de millones de registros.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /*
     * unique=true → constraint UNIQUE en la tabla MySQL.
     * nullable=false → NOT NULL en la tabla.
     * Esto garantiza integridad a nivel de BD, no solo a nivel de código.
     */
    @Column(nullable = false, unique = true, length = 150)
    private String email;

    @Column(nullable = false, length = 100)
    private String fullName;

    /*
     * La password llega aquí ya encriptada con BCrypt desde AuthService.
     * Nunca se guarda texto plano. Nunca.
     */
    @Column(nullable = false)
    private String password;

    /*
     * EnumType.STRING → guarda "ROLE_USER" en la BD, no un número.
     * Si mañana reordenas el enum, los datos existentes no se corrompen.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private Boolean active;

    /*
     * @PrePersist → Hibernate ejecuta este método justo antes del INSERT.
     * Centraliza la lógica de inicialización en la entidad misma.
     * Así nadie puede crear un User sin createdAt o sin active.
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.active = true;
    }

    /*
     * ABSTRACCIÓN: Role es un concepto propio del dominio bancario.
     * Vive dentro de User porque le pertenece semánticamente.
     * Para agregar ROLE_ADMIN solo tocas este enum, nada más.
     */
    public enum Role {
        ROLE_USER,
        ROLE_ADMIN
    }
}
