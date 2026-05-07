package kerberos_client;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;
import models.AS_REQ;
import models.AS_REP;
import models.TGS_REQ;
import models.TGS_REP;

/**
 * Interface representing the communication points to the Kerberos KDC (AS and TGS)
 * and the final Application Service.
 */
@RegisterRestClient(baseUri = "http://localhost:8080")
public interface KerberosRestClient {

    @POST
    @Path("/as_req")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    AS_REP authenticate(AS_REQ request);

    @POST
    @Path("/tgs_req")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    TGS_REP requestServiceTicket(TGS_REQ request);

    @GET
    @Path("/secure-data")
    @Produces(MediaType.APPLICATION_JSON)
    String getSecureData(@HeaderParam("Authorization") String authHeader);
}

