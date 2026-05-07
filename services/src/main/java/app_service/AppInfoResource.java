package app_service;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/app")
public class AppInfoResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public String info() {
        return """
            {
                "service": "Kerberos Protected Application Service",
                "description": "A secured resource that requires a valid Kerberos Service Ticket to access.",
                "endpoints": {
                    "GET /secure-data": "Access protected data (requires 'Authorization: Negotiate <token>' header).",
                    "GET /q/metrics": "Prometheus metrics endpoint."
                },
                "status": "RUNNING"
            }
            """;
    }
}
