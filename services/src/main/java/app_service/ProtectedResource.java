package app_service;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import models.AP_REQ;
import models.Authenticator;
import crypto.CryptoOperations;
import crypto.AesCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.value.ValueCommands;
import io.quarkus.redis.datasource.keys.KeyCommands;
import java.time.Duration;

import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/secure-data")
public class ProtectedResource {

    private final ObjectMapper objectMapper;
    private final CryptoOperations crypto;

    // app service key from env
    private final byte[] serviceKey;

    // redis cmds for cache
    private final ValueCommands<String, String> redisValueCommands;
    private final KeyCommands<String> redisKeyCommands;

    @Inject
    public ProtectedResource(
            RedisDataSource ds,
            @ConfigProperty(name = "APP_SERVICE_KEY") String appServiceKey) {
        this.objectMapper = new ObjectMapper();
        this.crypto = new AesCryptoService();
        this.serviceKey = appServiceKey.getBytes();

        this.redisValueCommands = ds.value(String.class);
        this.redisKeyCommands = ds.key();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSecureData(@HeaderParam("Authorization") String authHeader) {
        // kerberos negotiate scheme
        if (authHeader == null || !authHeader.startsWith("Negotiate ")) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .header("WWW-Authenticate", "Negotiate")
                    .entity("{\"error\": \"Missing or invalid Authorization header\"}")
                    .build();
        }

        try {
            // get token from header
            String token = authHeader.substring("Negotiate ".length());
            byte[] apReqBytes = Base64.getDecoder().decode(token);
            
            // deserialize ap_req
            AP_REQ apReq = objectMapper.readValue(apReqBytes, AP_REQ.class);

            // 1. decrypt service ticket
            byte[] stEncPart = apReq.getTicket().getEncPart();
            byte[] stIv = Arrays.copyOfRange(stEncPart, 0, 16);
            byte[] stCipher = Arrays.copyOfRange(stEncPart, 16, stEncPart.length);
            
            byte[] decryptedStBytes = crypto.decrypt(stCipher, serviceKey, stIv);
            Map<String, Object> stData = objectMapper.readValue(decryptedStBytes, new TypeReference<Map<String, Object>>() {});

            // 2. get session key from ticket
            String encodedSessionKey = (String) stData.get("sessionKey");
            byte[] serviceSessionKey = Base64.getDecoder().decode(encodedSessionKey);

            // 3. decrypt auth with session key
            byte[] authEncPart = apReq.getEncryptedAuthenticator();
            byte[] authIv = Arrays.copyOfRange(authEncPart, 0, 16);
            byte[] authCipher = Arrays.copyOfRange(authEncPart, 16, authEncPart.length);
            
            byte[] decryptedAuthBytes = crypto.decrypt(authCipher, serviceSessionKey, authIv);
            Authenticator authenticator = objectMapper.readValue(decryptedAuthBytes, Authenticator.class);

            // 4. check time skew
            long currentTime = System.currentTimeMillis();
            long clientTime = authenticator.getClientTimestamp();
            if (Math.abs(currentTime - clientTime) > 5 * 60 * 1000) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Authenticator expired or replay attack detected\"}").build();
            }

            // check redis for replays
            String replayKey = "replay:app:" + authenticator.getClientPrincipal().getPrincipalName() + ":" + clientTime;
            Boolean isNew = redisValueCommands.setnx(replayKey, "seen");
            
            if (isNew == null || !isNew) {
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("{\"error\": \"Replay Attack Detected: Authenticator already used\"}")
                               .build();
            }
            
            // set 5 min expiry
            redisKeyCommands.expire(replayKey, Duration.ofMinutes(5));
            
            // 5. return data
            String user = authenticator.getClientPrincipal().getPrincipalName();
            String jsonPayload = String.format(
                "{\"message\": \"Secret highly classified data successfully accessed!\", \"authenticatedUser\": \"%s\", \"balance\": \"$10,000,000\"}",
                user
            );
            return Response.ok(jsonPayload).build();

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.UNAUTHORIZED).entity("{\"error\": \"Authentication failed\"}").build();
        }
    }
}

