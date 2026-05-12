package com.bankcore.user.repository;


import com.bankcore.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long>{

    /*
     * QUERY AUTOMÁTICA — Spring Data lee el nombre del método y genera el SQL:
     * SELECT * FROM users WHERE email = ?
     *
     * Optional<User> en vez de User para forzar al caller a manejar
     * el caso "no existe" — evita NullPointerException por diseño.
     */
    Optional<User> findByEmail(String email);

    /*
     * QUERY AUTOMÁTICA:
     * SELECT COUNT(*) > 0 FROM users WHERE email = ?
     * Útil para validar duplicados antes de registrar.
     */
    boolean existsByEmail(String email);


    /*
     * JPQL — Java Persistence Query Language.
     * Es SQL pero sobre entidades Java, no sobre tablas directamente.
     * "u" es un alias de la entidad User.
     *
     * Equivalente SQL:
     * SELECT * FROM users WHERE active = true ORDER BY created_at DESC
     */
    @Query("SELECT u FROM User u WHERE u.active = true ORDER BY u.createdAt DESC")
    List<User> findAllActiveUsers();

    /*
     * JPQL CON PARÁMETRO NOMBRADO — @Param enlaza :role con el argumento.
     *
     * Equivalente SQL:
     * SELECT * FROM users WHERE role = ? AND active = true
     */
    @Query("SELECT u FROM User u WHERE u.role = :role AND u.active = true")
    List<User> findActiveUsersByRole(@Param("role") User.Role role);

    /*
     * NATIVE QUERY — SQL puro sobre la tabla real.
     * nativeQuery = true le dice a Spring que no interprete esto como JPQL.
     *
     * Úsala cuando necesitas funciones específicas de MySQL que JPQL no soporta,
     * o cuando el query es tan complejo que JPQL lo haría ilegible.
     *
     * COUNT(*) cuenta todos los usuarios activos agrupados por rol.
     */
    @Query(value = """
            SELECT role, COUNT(*) as total
            FROM users
            WHERE active = true
            GROUP BY role
            """, nativeQuery = true)
    List<Object[]> countActiveUsersByRole();

    /*
     * NATIVE QUERY CON BÚSQUEDA — LIKE para búsqueda parcial.
     *
     * CONCAT('%', :name, '%') construye el patrón dinámicamente.
     * Equivale a: WHERE full_name LIKE '%david%'
     *
     * En producción real esto iría paginado con Pageable.
     * Lo veremos en el módulo de Reports.
     */
    @Query(value = """
            SELECT * FROM users
            WHERE full_name LIKE CONCAT('%', :name, '%')
            AND active = true
            ORDER BY full_name ASC
            """, nativeQuery = true)
    List<User> searchByName(@Param("name") String name);

}
