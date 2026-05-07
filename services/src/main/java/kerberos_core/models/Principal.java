package models;

import java.util.Objects;

/**
 * Represents a Kerberos Principal (user or service).
 */
public class Principal implements KerberosEntity {
    
    private String name;
    private String realm;

    public Principal() {}

    public Principal(String name, String realm) {
        this.name = name;
        this.realm = realm;
    }

    @Override
    public String getPrincipalName() {
        return name;
    }

    public void setPrincipalName(String name) {
        this.name = name;
    }

    @Override
    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Principal principal = (Principal) o;
        return Objects.equals(name, principal.name) && Objects.equals(realm, principal.realm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, realm);
    }

    @Override
    public String toString() {
        return name + "@" + realm;
    }
}
