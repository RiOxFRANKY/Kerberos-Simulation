package models;

/**
 * Authentication Service Request.
 */
public class AS_REQ extends KdcReq {

    // message type 10 for AS_REQ
    public static final int MSG_TYPE = 10;

    // Pre-authentication data (PA-ENC-TIMESTAMP)
    private byte[] padata;

    public AS_REQ() {
        super(MSG_TYPE);
    }

    public byte[] getPadata() {
        return padata;
    }

    public void setPadata(byte[] padata) {
        this.padata = padata;
    }
}
