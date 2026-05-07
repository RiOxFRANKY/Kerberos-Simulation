package models;

/**
 * Represents a basic entity in the Kerberos protocol.
 */
public interface KerberosEntity {
    
    /**
     * Gets the principal name of the entity.
     * @return the principal name (e.g., alice, krbtgt/REALM)
     */
    String getPrincipalName();

    /**
     * Gets the realm of the entity.
     * @return the realm (e.g., EXAMPLE.COM)
     */
    String getRealm();
}
