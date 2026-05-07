package models;

/**
 * Represents a Ticket Granting Ticket (TGT).
 */
public class TGT extends Ticket {

    public TGT() {
        super();
    }

    public TGT(String realm, Principal serverPrincipal, byte[] encPart) {
        super(realm, serverPrincipal, encPart);
    }
}
