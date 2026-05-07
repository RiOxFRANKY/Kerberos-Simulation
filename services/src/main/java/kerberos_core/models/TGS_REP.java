package models;

/**
 * Ticket Granting Service Reply.
 */
public class TGS_REP extends KdcRep {

    // message type 13 for TGS_REP
    public static final int MSG_TYPE = 13;

    public TGS_REP() {
        super(MSG_TYPE);
    }
}
