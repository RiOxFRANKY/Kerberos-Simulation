package models;

/**
 * Represents the Authenticator sent by the client in AP_REQ.
 * It contains the client's timestamp to prevent replay attacks.
 */
public class Authenticator {

    private Principal clientPrincipal;
    private long clientTimestamp;
    private long clientMicroseconds;
    
    // Optional checksum of the application data
    private byte[] checksum;

    public Authenticator() {}

    public Authenticator(Principal clientPrincipal, long clientTimestamp, long clientMicroseconds) {
        this.clientPrincipal = clientPrincipal;
        this.clientTimestamp = clientTimestamp;
        this.clientMicroseconds = clientMicroseconds;
    }

    public Principal getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(Principal clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public long getClientTimestamp() {
        return clientTimestamp;
    }

    public void setClientTimestamp(long clientTimestamp) {
        this.clientTimestamp = clientTimestamp;
    }

    public long getClientMicroseconds() {
        return clientMicroseconds;
    }

    public void setClientMicroseconds(long clientMicroseconds) {
        this.clientMicroseconds = clientMicroseconds;
    }

    public byte[] getChecksum() {
        return checksum;
    }

    public void setChecksum(byte[] checksum) {
        this.checksum = checksum;
    }
}
