package models;

/**
 * Authentication Service Reply.
 */
public class AS_REP extends KdcRep {

    // message type 11 for AS_REP
    public static final int MSG_TYPE = 11;

    public AS_REP() {
        super(MSG_TYPE);
    }
}
