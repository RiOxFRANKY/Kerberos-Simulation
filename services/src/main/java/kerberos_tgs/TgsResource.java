package kerberos_tgs;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import models.TGS_REQ;
import models.TGS_REP;
import models.ServiceTicket;
import models.AP_REQ;
import models.Authenticator;
import crypto.CryptoOperations;
import crypto.AesCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.value.ValueCommands;
import io.quarkus.redis.datasource.keys.KeyCommands;
import jakarta.inject.Inject;
import java.time.Duration;

import io.micrometer.core.instrument.MeterRegistry;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@Path("/tgs_req")
public class TgsResource {

    private final CryptoOperations crypto;
    private final ObjectMapper objectMapper;

    // kdc master key from env
    private final byte[] kdcMasterKey;
    
    // mock db for services
    private final Map<String, byte[]> mockServiceDb;
    
    // redis cmds for cache
    private final ValueCommands<String, String> redisValueCommands;
    private final KeyCommands<String> redisKeyCommands;
    
    @Inject
    MeterRegistry registry;

    @Inject
    public TgsResource(
            RedisDataSource ds,
            @ConfigProperty(name = "KDC_MASTER_KEY") String masterKey,
            @ConfigProperty(name = "APP_SERVICE_KEY") String appServiceKey) {
        this.crypto = new AesCryptoService();
        this.objectMapper = new ObjectMapper();
        this.kdcMasterKey = masterKey.getBytes();
        this.mockServiceDb = new HashMap<>();
        this.mockServiceDb.put("app-service", appServiceKey.getBytes());
        
        this.redisValueCommands = ds.value(String.class);
        this.redisKeyCommands = ds.key();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response requestServiceTicket(TGS_REQ request) {
        try {
            // 1. get ap_req from padata
            AP_REQ apReq = objectMapper.readValue(request.getPadata(), AP_REQ.class);
            
            // 2. decrypt tgt with master key
            byte[] tgtEncPart = apReq.getTicket().getEncPart();
            byte[] tgtIv = Arrays.copyOfRange(tgtEncPart, 0, 16);
            byte[] tgtCipher = Arrays.copyOfRange(tgtEncPart, 16, tgtEncPart.length);
            
            byte[] decryptedTgtBytes = crypto.decrypt(tgtCipher, kdcMasterKey, tgtIv);
            Map<String, Object> tgtData = objectMapper.readValue(decryptedTgtBytes, new TypeReference<Map<String, Object>>() {});
            
            String encodedSessionKey = (String) tgtData.get("sessionKey");
            byte[] tgtSessionKey = Base64.getDecoder().decode(encodedSessionKey);

            // 3. check auth with session key
            byte[] authEncPart = apReq.getEncryptedAuthenticator();
            byte[] authIv = Arrays.copyOfRange(authEncPart, 0, 16);
            byte[] authCipher = Arrays.copyOfRange(authEncPart, 16, authEncPart.length);
            
            byte[] decryptedAuthBytes = crypto.decrypt(authCipher, tgtSessionKey, authIv);
            Authenticator authenticator = objectMapper.readValue(decryptedAuthBytes, Authenticator.class);
            
            // 4. check time skew
            long currentTime = System.currentTimeMillis();
            long clientTime = authenticator.getClientTimestamp();
            if (Math.abs(currentTime - clientTime) > 5 * 60 * 1000) {
                registry.counter("auth_requests_total", "service", "tgs", "result", "failure").increment();
                return Response.status(Response.Status.UNAUTHORIZED).entity("Authenticator expired or replay attack detected").build();
            }

            // check redis for replays
            // use user and time as key
            String replayKey = "replay:tgs:" + authenticator.getClientPrincipal().getPrincipalName() + ":" + clientTime;
            Boolean isNew = redisValueCommands.setnx(replayKey, "seen");
            
            if (isNew == null || !isNew) {
                registry.counter("auth_requests_total", "service", "tgs", "result", "failure").increment();
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("Replay Attack Detected: Authenticator already used")
                               .build();
            }
            
            // set 5 min expiry
            redisKeyCommands.expire(replayKey, Duration.ofMinutes(5));

            // 5. see if service exists
            String targetServiceName = request.getServerPrincipal().getPrincipalName();
            if (!mockServiceDb.containsKey(targetServiceName)) {
                registry.counter("auth_requests_total", "service", "tgs", "result", "failure").increment();
                return Response.status(Response.Status.NOT_FOUND).entity("Service not found").build();
            }
            byte[] targetServiceKey = mockServiceDb.get(targetServiceName);

            // 6. make service session key
            byte[] serviceSessionKey = crypto.generateSessionKey();

            // 7. make service ticket
            ServiceTicket serviceTicket = new ServiceTicket();
            serviceTicket.setRealm(request.getServerPrincipal().getRealm());
            serviceTicket.setServerPrincipal(request.getServerPrincipal());
            
            // encrypt ticket data
            Map<String, Object> stEncData = new HashMap<>();
            stEncData.put("sessionKey", Base64.getEncoder().encodeToString(serviceSessionKey));
            stEncData.put("clientPrincipal", authenticator.getClientPrincipal());
            stEncData.put("timestamp", System.currentTimeMillis());
            
            byte[] stIv = crypto.generateIv();
            byte[] encryptedSt = crypto.encrypt(objectMapper.writeValueAsBytes(stEncData), targetServiceKey, stIv);
            serviceTicket.setEncPart(combineIvAndCiphertext(stIv, encryptedSt));

            // 8. make tgs_rep
            TGS_REP reply = new TGS_REP();
            reply.setClientPrincipal(authenticator.getClientPrincipal());
            reply.setTicket(serviceTicket);
            
            // encrypt tgs_rep
            Map<String, Object> repEncData = new HashMap<>();
            repEncData.put("sessionKey", Base64.getEncoder().encodeToString(serviceSessionKey));
            repEncData.put("nonce", request.getNonce());
            repEncData.put("serverPrincipal", request.getServerPrincipal());
            
            byte[] repIv = crypto.generateIv();
            byte[] encryptedRep = crypto.encrypt(objectMapper.writeValueAsBytes(repEncData), tgtSessionKey, repIv);
            reply.setEncPart(combineIvAndCiphertext(repIv, encryptedRep));

            registry.counter("auth_requests_total", "service", "tgs", "result", "success").increment();
            return Response.ok(reply).build();
            
        } catch (Exception e) {
            e.printStackTrace();
            registry.counter("auth_requests_total", "service", "tgs", "result", "error").increment();
            return Response.serverError().entity("Internal Server Error").build();
        }
    }
    
    // stick iv on ciphertext
    private byte[] combineIvAndCiphertext(byte[] iv, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }
}

