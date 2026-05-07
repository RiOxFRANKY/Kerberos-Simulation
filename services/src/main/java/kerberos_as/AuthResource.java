package kerberos_as;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.transaction.Transactional;
import models.AS_REQ;
import models.AS_REP;
import models.TGT;
import models.Authenticator;
import crypto.CryptoOperations;
import crypto.AesCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/as_req")
public class AuthResource {

    private final CryptoOperations crypto;
    private final ObjectMapper objectMapper;
    
    @Inject
    MeterRegistry registry;
    
    // kdc master key from env
    private final byte[] kdcMasterKey;

    @Inject
    public AuthResource(
            @ConfigProperty(name = "KDC_MASTER_KEY") String masterKey,
            // keep these for compat
            @ConfigProperty(name = "MOCK_USER_NAME", defaultValue = "alice") String userName,
            @ConfigProperty(name = "MOCK_USER_KEY", defaultValue = "unused") String userKey) {
        this.crypto = new AesCryptoService();
        this.objectMapper = new ObjectMapper();
        this.kdcMasterKey = masterKey.getBytes();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Transactional
    public Response authenticate(AS_REQ request) {
        try {
            String clientName = request.getClientPrincipal().getPrincipalName();
            System.out.println("[DEBUG AS] clientName received: '" + clientName + "'");
            
            // 1. find user in db
            PrincipalEntity principal = PrincipalEntity.findByUsername(clientName);
            System.out.println("[DEBUG AS] principal found: " + (principal != null ? principal.username : "NULL"));
            if (principal == null) {
                registry.counter("auth_requests_total", "service", "as", "result", "failure").increment();
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"error\": \"Principal not found in KDC database\"}")
                        .build();
            }

            // 2. get user key from hash
            // encrypts as_rep for user
            byte[] userKey = Base64.getDecoder().decode(principal.passwordHash);

            // 3. check pre-auth
            byte[] padata = request.getPadata();
            if (padata == null || padata.length == 0) {
                registry.counter("auth_requests_total", "service", "as", "result", "failure_preauth").increment();
                return Response.status(Response.Status.UNAUTHORIZED)
                        .header("WWW-Authenticate", "Kerberos")
                        .entity("{\"error\": \"Pre-Authentication Required (PA-ENC-TIMESTAMP)\"}")
                        .build();
            }

            try {
                byte[] paIv = java.util.Arrays.copyOfRange(padata, 0, 16);
                byte[] paCipher = java.util.Arrays.copyOfRange(padata, 16, padata.length);
                byte[] decryptedPa = crypto.decrypt(paCipher, userKey, paIv);
                Authenticator preAuth = objectMapper.readValue(decryptedPa, Authenticator.class);

                // check 5 min skew
                long currentTime = System.currentTimeMillis();
                long clientTime = preAuth.getClientTimestamp();
                if (Math.abs(currentTime - clientTime) > 5 * 60 * 1000) {
                    throw new RuntimeException("Pre-Auth timestamp expired or replayed");
                }
            } catch (Exception e) {
                registry.counter("auth_requests_total", "service", "as", "result", "failure_preauth").increment();
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"error\": \"Pre-Authentication Failed (Invalid Password or Expired Timestamp)\"}")
                        .build();
            }

            // 4. make session key
            byte[] sessionKey = crypto.generateSessionKey();

            // 5. make tgt
            TGT tgt = new TGT();
            tgt.setRealm(request.getServerPrincipal().getRealm());
            tgt.setServerPrincipal(request.getServerPrincipal());
            
            // encrypt tgt data
            Map<String, Object> tgtEncData = new HashMap<>();
            tgtEncData.put("sessionKey", Base64.getEncoder().encodeToString(sessionKey));
            tgtEncData.put("clientPrincipal", request.getClientPrincipal());
            tgtEncData.put("timestamp", System.currentTimeMillis());
            
            byte[] tgtIv = crypto.generateIv();
            byte[] encryptedTgt = crypto.encrypt(objectMapper.writeValueAsBytes(tgtEncData), kdcMasterKey, tgtIv);
            tgt.setEncPart(combineIvAndCiphertext(tgtIv, encryptedTgt));

            // 6. make as_rep
            AS_REP reply = new AS_REP();
            reply.setClientPrincipal(request.getClientPrincipal());
            reply.setTicket(tgt);
            
            // encrypt as_rep data
            Map<String, Object> repEncData = new HashMap<>();
            repEncData.put("sessionKey", Base64.getEncoder().encodeToString(sessionKey));
            repEncData.put("nonce", request.getNonce());
            repEncData.put("serverPrincipal", request.getServerPrincipal());
            
            byte[] repIv = crypto.generateIv();
            byte[] encryptedRep = crypto.encrypt(objectMapper.writeValueAsBytes(repEncData), userKey, repIv);
            reply.setEncPart(combineIvAndCiphertext(repIv, encryptedRep));

            registry.counter("auth_requests_total", "service", "as", "result", "success").increment();
            return Response.ok(reply).build();
            
        } catch (Exception e) {
            e.printStackTrace();
            registry.counter("auth_requests_total", "service", "as", "result", "error").increment();
            return Response.serverError().entity("{\"error\": \"Internal Server Error\"}").build();
        }
    }
    
    // helper to stick iv to front of ciphertext
    private byte[] combineIvAndCiphertext(byte[] iv, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }
}
