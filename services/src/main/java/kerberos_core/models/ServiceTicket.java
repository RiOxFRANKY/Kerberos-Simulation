package models;

/**
 * Represents a Service Ticket used to authenticate against a specific application service.
 */
public class ServiceTicket extends Ticket {

    public ServiceTicket() {
        super();
    }

    public ServiceTicket(String realm, Principal serverPrincipal, byte[] encPart) {
        super(realm, serverPrincipal, encPart);
    }
}
