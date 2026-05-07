package models;

/**
 * Abstract base class for all Kerberos messages.
 */
public abstract class KerberosMessage {
    
    // Protocol Version Number (usually 5)
    private int pvno = 5;
    
    // Message Type (e.g., 10 for AS_REQ, 11 for AS_REP)
    private int msgType;

    public KerberosMessage(int msgType) {
        this.msgType = msgType;
    }

    public int getPvno() {
        return pvno;
    }

    public void setPvno(int pvno) {
        this.pvno = pvno;
    }

    public int getMsgType() {
        return msgType;
    }

    public void setMsgType(int msgType) {
        this.msgType = msgType;
    }
}
