package models;

/**
 * Abstract base class for all KDC Replies (AS_REP, TGS_REP).
 */
public abstract class KdcRep extends KerberosMessage {

    private Principal clientPrincipal;
    private Ticket ticket;
    
    // The encrypted part of the reply, intended for the client
    private byte[] encPart;

    public KdcRep(int msgType) {
        super(msgType);
    }

    public Principal getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(Principal clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public byte[] getEncPart() {
        return encPart;
    }

    public void setEncPart(byte[] encPart) {
        this.encPart = encPart;
    }
}
