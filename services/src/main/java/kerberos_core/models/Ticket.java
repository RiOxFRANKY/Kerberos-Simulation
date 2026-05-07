package models;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * Abstract base class for all Kerberos Tickets.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "ticketType")
@JsonSubTypes({
    @JsonSubTypes.Type(value = TGT.class, name = "TGT"),
    @JsonSubTypes.Type(value = ServiceTicket.class, name = "ST")
})
public abstract class Ticket {
    
    private String realm;
    private Principal serverPrincipal;
    
    // The encrypted part of the ticket (usually contains session key, client principal, timestamps)
    private byte[] encPart;

    public Ticket() {}

    public Ticket(String realm, Principal serverPrincipal, byte[] encPart) {
        this.realm = realm;
        this.serverPrincipal = serverPrincipal;
        this.encPart = encPart;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public Principal getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(Principal serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public byte[] getEncPart() {
        return encPart;
    }

    public void setEncPart(byte[] encPart) {
        this.encPart = encPart;
    }
}
