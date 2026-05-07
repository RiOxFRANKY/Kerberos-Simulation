package kerberos_as;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Exposes the salt for a given principal. In real Kerberos (RFC 4120),
 * the client derives its long-term key using password + salt. The salt
 * is NOT secret — it simply ensures two users with the same password
 * produce different keys.
 */
@Path("/as/salt")
public class SaltResource {

    @GET
    @Path("/{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSalt(@PathParam("username") String username) {
        PrincipalEntity principal = PrincipalEntity.findByUsername(username);
        if (principal == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\": \"Principal not found\"}")
                    .build();
        }
        return Response.ok("{\"salt\": \"" + principal.salt + "\"}").build();
    }
}
