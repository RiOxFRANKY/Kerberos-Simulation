package kerberos_as;

import io.quarkus.hibernate.orm.panache.PanacheEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * Represents a Kerberos Principal record stored in the KDC database.
 * Each record has a unique username, a password hash (derived via PBKDF2),
 * and a cryptographic salt used during key derivation.
 *
 * Named "PrincipalEntity" to avoid conflict with the Kerberos protocol
 * Principal class (models.Principal) which represents name+realm identifiers.
 */
@Entity
@Table(name = "principals")
public class PrincipalEntity extends PanacheEntity {

    @Column(unique = true, nullable = false)
    public String username;

    /**
     * The derived key (password hash) stored as a Base64-encoded string.
     * This is the 32-byte AES-256 key used to encrypt AS_REP data for this principal.
     */
    @Column(name = "password_hash", nullable = false)
    public String passwordHash;

    /**
     * A random salt used during key derivation (e.g., PBKDF2).
     * Stored as a Base64-encoded string.
     */
    @Column(nullable = false)
    public String salt;

    // --- Panache helper methods ---

    /**
     * Find a principal by their username.
     *
     * @param username the principal name (e.g., "alice", "krbtgt/REALM")
     * @return the PrincipalEntity or null if not found
     */
    public static PrincipalEntity findByUsername(String username) {
        return find("username = ?1", username).firstResult();
    }
}
