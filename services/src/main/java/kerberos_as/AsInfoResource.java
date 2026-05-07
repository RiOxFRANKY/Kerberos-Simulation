package kerberos_as;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/as")
public class AsInfoResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String info() {
        return """
            {
                "service": "Kerberos Authentication Service (AS)",
                "description": "Issues Ticket Granting Tickets (TGTs) to authenticated users.",
                "endpoints": {
                    "POST /as_req": "Submit an AS_REQ to authenticate and receive a TGT.",
                    "GET /q/metrics": "Prometheus metrics endpoint."
                },
                "status": "RUNNING"
            }
            """;
    }
}
