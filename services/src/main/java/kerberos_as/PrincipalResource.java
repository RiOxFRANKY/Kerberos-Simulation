package kerberos_as;

import crypto.AesCryptoService;
import crypto.CryptoOperations;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Base64;
import java.util.Map;

/**
 * Admin endpoint for managing principals in the KDC database.
 * In production, this would be secured behind mTLS or an admin token.
 * For the simulation, it allows seeding users into the kerberos_registry DB.
 */
@Path("/admin/principals")
public class PrincipalResource {

    private final CryptoOperations crypto = new AesCryptoService();

    /**
     * Register a new principal in the KDC database.
     * 
     * Request body: { "username": "alice", "password": "secret" }
     * 
     * The password is hashed with PBKDF2 (310,000 iterations) and a random salt
     * before being stored. The plaintext password is never persisted.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response registerPrincipal(Map<String, String> body) {
        try {
            String username = body.get("username");
            String password = body.get("password");

            if (username == null || password == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\": \"Both 'username' and 'password' are required\"}")
                        .build();
            }

            // Check if principal already exists
            if (PrincipalEntity.findByUsername(username) != null) {
                return Response.status(Response.Status.CONFLICT)
                        .entity("{\"error\": \"Principal '" + username + "' already exists\"}")
                        .build();
            }

            // Generate salt and derive key
            byte[] salt = crypto.generateSalt();
            byte[] derivedKey = crypto.deriveKey(password, salt);

            // Store the principal
            PrincipalEntity principal = new PrincipalEntity();
            principal.username = username;
            principal.passwordHash = Base64.getEncoder().encodeToString(derivedKey);
            principal.salt = Base64.getEncoder().encodeToString(salt);
            principal.persist();

            return Response.status(Response.Status.CREATED)
                    .entity("{\"message\": \"Principal '" + username + "' registered successfully\"}")
                    .build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.serverError()
                    .entity("{\"error\": \"Failed to register principal\"}")
                    .build();
        }
    }

    /**
     * List all registered principals (usernames only, no secrets).
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listPrincipals() {
        return Response.ok(
                PrincipalEntity.find("SELECT p.username FROM PrincipalEntity p ORDER BY p.username").list()
        ).build();
    }
}
