package kerberos_tgs;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/tgs")
public class TgsInfoResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String info() {
        return """
            {
                "service": "Kerberos Ticket Granting Service (TGS)",
                "description": "Validates TGTs and issues Service Tickets for target applications.",
                "endpoints": {
                    "POST /tgs_req": "Submit a TGS_REQ with a valid TGT to receive a Service Ticket.",
                    "GET /q/metrics": "Prometheus metrics endpoint."
                },
                "security": "Redis-backed replay cache enabled.",
                "status": "RUNNING"
            }
            """;
    }
}
