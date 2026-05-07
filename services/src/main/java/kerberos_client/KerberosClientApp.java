package kerberos_client;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import jakarta.inject.Inject;

import models.AS_REQ;
import models.AS_REP;
import models.TGS_REQ;
import models.TGS_REP;
import models.AP_REQ;
import models.Principal;
import models.Ticket;
import models.Authenticator;
import crypto.CryptoOperations;
import crypto.AesCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

@QuarkusMain(name="client")
public class KerberosClientApp implements QuarkusApplication {

    @Inject
    @RestClient
    KerberosRestClient restClient;

    private final CryptoOperations crypto = new AesCryptoService();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public int run(String... args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java -jar kerberos-client.jar <username> <password>");
            System.err.println("Example: java -jar kerberos-client.jar alice passwordhash_32bytes_long_123456");
            return 1;
        }

        String username = args[0];
        String passwordHash = args[1]; // Using the 32-byte hash directly for simulation

        System.out.println("=================================================");
        System.out.println("Starting Kerberos Client Simulation");
        System.out.println("User: " + username);
        System.out.println("=================================================");

        try {
            // ---------------------------------------------------------
            // 1. AS_REQ (Authentication Service)
            // ---------------------------------------------------------
            Principal clientPrincipal = new Principal(username, "REALM.COM");
            Principal krbtgt = new Principal("krbtgt/REALM.COM", "REALM.COM");

            AS_REQ asReq = new AS_REQ();
            asReq.setClientPrincipal(clientPrincipal);
            asReq.setServerPrincipal(krbtgt);
            asReq.setNonce(crypto.generateNonce());

            System.out.println("[1/4] Sending AS_REQ to Authentication Service...");
            AS_REP asRep = restClient.authenticate(asReq);
            System.out.println("      <- Received AS_REP.");

            // Decrypt AS_REP using user's password hash
            byte[] userKey = passwordHash.getBytes();
            byte[] asRepEnc = asRep.getEncPart();
            byte[] asRepIv = Arrays.copyOfRange(asRepEnc, 0, 16);
            byte[] asRepCipher = Arrays.copyOfRange(asRepEnc, 16, asRepEnc.length);

            byte[] decryptedAsRep = crypto.decrypt(asRepCipher, userKey, asRepIv);
            Map<String, Object> asRepData = objectMapper.readValue(decryptedAsRep, new TypeReference<Map<String, Object>>() {});

            String asSessionKeyEncoded = (String) asRepData.get("sessionKey");
            byte[] asSessionKey = Base64.getDecoder().decode(asSessionKeyEncoded);
            Ticket tgt = asRep.getTicket();
            System.out.println("      [+] Successfully decrypted AS Session Key and extracted TGT.");

            // ---------------------------------------------------------
            // 2. TGS_REQ (Ticket Granting Service)
            // ---------------------------------------------------------
            Principal appService = new Principal("app-service", "REALM.COM");

            TGS_REQ tgsReq = new TGS_REQ();
            tgsReq.setClientPrincipal(clientPrincipal);
            tgsReq.setServerPrincipal(appService);
            tgsReq.setNonce(crypto.generateNonce());

            // Create Authenticator for TGS
            Authenticator tgsAuth = new Authenticator(clientPrincipal, System.currentTimeMillis(), 0);
            byte[] tgsAuthBytes = objectMapper.writeValueAsBytes(tgsAuth);
            byte[] tgsAuthIv = crypto.generateIv();
            byte[] tgsAuthCipher = crypto.encrypt(tgsAuthBytes, asSessionKey, tgsAuthIv);

            // Create AP_REQ to embed in padata
            AP_REQ padataApReq = new AP_REQ();
            padataApReq.setTicket(tgt); // Send TGT as the ticket
            padataApReq.setEncryptedAuthenticator(combineIvAndCiphertext(tgsAuthIv, tgsAuthCipher));

            tgsReq.setPadata(objectMapper.writeValueAsBytes(padataApReq));

            System.out.println("\n[2/4] Sending TGS_REQ to Ticket Granting Service...");
            TGS_REP tgsRep = restClient.requestServiceTicket(tgsReq);
            System.out.println("      <- Received TGS_REP.");

            // ---------------------------------------------------------
            // 3. Extract Service Ticket
            // ---------------------------------------------------------
            byte[] tgsRepEnc = tgsRep.getEncPart();
            byte[] tgsRepIv = Arrays.copyOfRange(tgsRepEnc, 0, 16);
            byte[] tgsRepCipher = Arrays.copyOfRange(tgsRepEnc, 16, tgsRepEnc.length);

            byte[] decryptedTgsRep = crypto.decrypt(tgsRepCipher, asSessionKey, tgsRepIv);
            Map<String, Object> tgsRepData = objectMapper.readValue(decryptedTgsRep, new TypeReference<Map<String, Object>>() {});

            String tgsSessionKeyEncoded = (String) tgsRepData.get("sessionKey");
            byte[] serviceSessionKey = Base64.getDecoder().decode(tgsSessionKeyEncoded);
            Ticket serviceTicket = tgsRep.getTicket();
            System.out.println("      [+] Successfully decrypted Service Session Key and extracted Service Ticket.");

            // ---------------------------------------------------------
            // 4. AP_REQ (Application Service)
            // ---------------------------------------------------------
            Authenticator appAuth = new Authenticator(clientPrincipal, System.currentTimeMillis(), 0);
            byte[] appAuthBytes = objectMapper.writeValueAsBytes(appAuth);
            byte[] appAuthIv = crypto.generateIv();
            byte[] appAuthCipher = crypto.encrypt(appAuthBytes, serviceSessionKey, appAuthIv);

            AP_REQ finalApReq = new AP_REQ();
            finalApReq.setTicket(serviceTicket);
            finalApReq.setEncryptedAuthenticator(combineIvAndCiphertext(appAuthIv, appAuthCipher));

            String base64Token = Base64.getEncoder().encodeToString(objectMapper.writeValueAsBytes(finalApReq));

            System.out.println("\n[3/4] Sending AP_REQ to App Service via Authorization header...");
            String secureData = restClient.getSecureData("Negotiate " + base64Token);

            System.out.println("\n[4/4] SUCCESS! Final Secure Data Received:");
            System.out.println("      " + secureData);
            System.out.println("=================================================");
            
        } catch (Exception e) {
            System.err.println("\n[X] Kerberos flow failed: " + e.getMessage());
            e.printStackTrace();
        }

        return 0;
    }
    
    private byte[] combineIvAndCiphertext(byte[] iv, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }
}

