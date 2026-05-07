package models;

/**
 * Ticket Granting Service Request.
 */
public class TGS_REQ extends KdcReq {

    // message type 12 for TGS_REQ
    public static final int MSG_TYPE = 12;

    // The TGT is sent as part of the padata (pre-authentication data) in a real implementation
    private byte[] padata;

    public TGS_REQ() {
        super(MSG_TYPE);
    }

    public byte[] getPadata() {
        return padata;
    }

    public void setPadata(byte[] padata) {
        this.padata = padata;
    }
}
