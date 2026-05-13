package com.bankcore.auth.dto;

import jakarta.validation.constraints.*;
import lombok.Data;
/*
 * DTO de entrada para POST /api/auth/register.
 *
 * POR QUÉ no usamos la entidad User directamente:
 * 1. User tiene campos que el cliente no debe enviar (id, createdAt, role, active).
 * 2. Las validaciones del DTO son del contrato HTTP, no de la BD.
 * 3. Si cambia la API no tocamos la entidad, y viceversa.
 *
 * Separación de responsabilidades en acción.
 */


@Data
public class RegisterRequest {

    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 2, max = 100, message = "El nombre debe tener entre 2 y 100 caracteres")
    private String fullName;

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "Formato de email inválido")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener mínimo 8 caracteres")
    private String password;
}
