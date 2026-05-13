package com.bankcore.auth.dto;


import jakarta.validation.constraints.*;
import lombok.Data;

/*
 * DTO de entrada para POST /api/auth/login.
 * Solo necesita email y password — nada más entra por este endpoint.
 */
@Data
public class LoginRequest {

    @NotBlank(message = "El email es obligatorio")
    @Email(message = "Formato de email inválido")
    private String email;

    @NotBlank(message = "La contraseña es obligatoria")
    private String password;
}
