package models;

/**
 * Abstract base class for all KDC Requests (AS_REQ, TGS_REQ).
 */
public abstract class KdcReq extends KerberosMessage {

    private Principal clientPrincipal;
    private Principal serverPrincipal;
    private long nonce;

    public KdcReq(int msgType) {
        super(msgType);
    }

    public Principal getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(Principal clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public Principal getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(Principal serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public long getNonce() {
        return nonce;
    }

    public void setNonce(long nonce) {
        this.nonce = nonce;
    }
}
