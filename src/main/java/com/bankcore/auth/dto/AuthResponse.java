package com.bankcore.auth.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

/*
 * DTO de salida — lo que el servidor devuelve tras login o register exitoso.
 *
 * El cliente recibe este token y lo envía en cada request siguiente
 * en el header HTTP: Authorization: Bearer <token>
 *
 * Nunca devolvemos la password, nunca devolvemos el id interno.
 * Solo lo que el cliente necesita para operar.
 */
@Data
@Builder
@AllArgsConstructor
public class AuthResponse {

    private String token;
    private String email;
    private String fullName;
    private String role;
}
