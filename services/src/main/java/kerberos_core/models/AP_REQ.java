package models;

/**
 * Application Request, used by the client to authenticate to the final Application Service.
 */
public class AP_REQ extends KerberosMessage {

    // message type 14 for AP_REQ
    public static final int MSG_TYPE = 14;

    private Ticket ticket;
    
    // The authenticator, encrypted with the session key from the service ticket
    private byte[] encryptedAuthenticator;

    public AP_REQ() {
        super(MSG_TYPE);
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public byte[] getEncryptedAuthenticator() {
        return encryptedAuthenticator;
    }

    public void setEncryptedAuthenticator(byte[] encryptedAuthenticator) {
        this.encryptedAuthenticator = encryptedAuthenticator;
    }
}
