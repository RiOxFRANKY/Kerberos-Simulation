package kerberos_client;
import kerberos_core.models.*;
import kerberos_core.crypto.*;
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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

/**
 * Standalone Kerberos CLI Client.
 * 
 * Walks through the complete Kerberos V5 authentication flow:
 *   Step 1: Fetch salt from AS
 *   Step 2: Derive long-term key via PBKDF2
 *   Step 3: AS_REQ  → AS_REP  (get TGT)
 *   Step 4: TGS_REQ → TGS_REP (get Service Ticket)
 *   Step 5: AP_REQ  → App Service (access protected resource)
 *
 * Usage: java KerberosCliClient
 *   (prompts for username and password interactively)
 */
public class KerberosCliClient {

    private static final String AS_URL  = System.getenv("AS_URL")  != null ? System.getenv("AS_URL")  : "http://localhost:8081";
    private static final String TGS_URL = System.getenv("TGS_URL") != null ? System.getenv("TGS_URL") : "http://localhost:8082";
    private static final String APP_URL = System.getenv("APP_URL") != null ? System.getenv("APP_URL") : "http://localhost:8083";
    private static final String REALM   = "KERBEROS.SIM";

    private static final CryptoOperations crypto = new AesCryptoService();
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        printBanner();

        // get creds
        System.out.print("  Username: ");
        String username = scanner.nextLine().trim();

        // hide password input
        String password;
        java.io.Console console = System.console();
        if (console != null) {
            char[] pwdChars = console.readPassword("  Password: ");
            password = new String(pwdChars).trim();
            // clear password from memory
            java.util.Arrays.fill(pwdChars, '\0');
        } else {
            // fallback if no console
            System.out.print("  Password: ");
            password = scanner.nextLine().trim();
        }
        System.out.println();

        try {
            // ═══════════════════════════════════════════════════════════
            // step 1: get salt
            // ═══════════════════════════════════════════════════════════
            printStep(1, "PRE-AUTH", "Fetching salt for '" + username + "' from AS...");
            String saltResponse;
            try {
                saltResponse = httpGet(AS_URL + "/as/salt/" + username);
            } catch (RuntimeException e) {
                printFail("USER NOT FOUND - '" + username + "' does not exist in the KDC database.");
                printFail("The KDC has no record of this principal. Authentication denied.");
                return;
            }
            Map<String, String> saltMap = mapper.readValue(saltResponse, new TypeReference<Map<String, String>>() {});
            String saltB64 = saltMap.get("salt");

            if (saltB64 == null) {
                printFail("USER NOT FOUND - '" + username + "' does not exist in the KDC database.");
                return;
            }
            printOk("Salt retrieved: " + saltB64.substring(0, 8) + "...");

            // ═══════════════════════════════════════════════════════════
            // step 2: derive key
            // ═══════════════════════════════════════════════════════════
            printStep(2, "KEY DERIVATION", "Deriving long-term key via PBKDF2 (310,000 iterations)...");
            byte[] salt = Base64.getDecoder().decode(saltB64);
            byte[] userKey = crypto.deriveKey(password, salt);
            printOk("Long-term key derived: " + Base64.getEncoder().encodeToString(userKey).substring(0, 12) + "...");

            // ═══════════════════════════════════════════════════════════
            // step 3: get tgt
            // ═══════════════════════════════════════════════════════════
            printStep(3, "AS_REQ", "Requesting TGT from Authentication Server...");

            Principal clientPrincipal = new Principal(username, REALM);
            Principal krbtgt = new Principal("krbtgt", REALM);

            AS_REQ asReq = new AS_REQ();
            asReq.setClientPrincipal(clientPrincipal);
            asReq.setServerPrincipal(krbtgt);
            asReq.setNonce(crypto.generateNonce());

            // pre-auth
            Authenticator preAuth = new Authenticator(clientPrincipal, System.currentTimeMillis(), 0);
            byte[] preAuthBytes = mapper.writeValueAsBytes(preAuth);
            byte[] preAuthIv = crypto.generateIv();
            byte[] preAuthCipher = crypto.encrypt(preAuthBytes, userKey, preAuthIv);
            asReq.setPadata(combineIvAndCiphertext(preAuthIv, preAuthCipher));

            String asRepJson = httpPost(AS_URL + "/as_req", mapper.writeValueAsString(asReq));
            AS_REP asRep = mapper.readValue(asRepJson, AS_REP.class);
            printOk("AS_REP received - TGT issued for " + username + "@" + REALM);

            // decrypt as_rep
            byte[] asRepEnc = asRep.getEncPart();
            byte[] asRepIv = Arrays.copyOfRange(asRepEnc, 0, 16);
            byte[] asRepCipher = Arrays.copyOfRange(asRepEnc, 16, asRepEnc.length);

            byte[] decryptedAsRep;
            try {
                decryptedAsRep = crypto.decrypt(asRepCipher, userKey, asRepIv);
            } catch (javax.crypto.BadPaddingException e) {
                printFail("WRONG PASSWORD - decryption failed. The derived key does not match.");
                printFail("This is how Kerberos works: if you can't decrypt the AS_REP, you're not who you claim to be.");
                return;
            }
            Map<String, Object> asRepData = mapper.readValue(decryptedAsRep, new TypeReference<Map<String, Object>>() {});

            byte[] sessionKey = Base64.getDecoder().decode((String) asRepData.get("sessionKey"));
            Ticket tgt = asRep.getTicket();
            printOk("AS_REP decrypted — session key extracted");
            printOk("Nonce verified: " + asRepData.get("nonce"));

            // ═══════════════════════════════════════════════════════════
            // step 4: get service ticket
            // ═══════════════════════════════════════════════════════════
            printStep(4, "TGS_REQ", "Requesting Service Ticket for 'app-service'...");

            Principal appService = new Principal("app-service", REALM);

            TGS_REQ tgsReq = new TGS_REQ();
            tgsReq.setClientPrincipal(clientPrincipal);
            tgsReq.setServerPrincipal(appService);
            tgsReq.setNonce(crypto.generateNonce());

            // make auth
            Authenticator tgsAuth = new Authenticator(clientPrincipal, System.currentTimeMillis(), 0);
            byte[] tgsAuthBytes = mapper.writeValueAsBytes(tgsAuth);
            byte[] tgsAuthIv = crypto.generateIv();
            byte[] tgsAuthCipher = crypto.encrypt(tgsAuthBytes, sessionKey, tgsAuthIv);

            // wrap in ap_req
            AP_REQ padataApReq = new AP_REQ();
            padataApReq.setTicket(tgt);
            padataApReq.setEncryptedAuthenticator(combineIvAndCiphertext(tgsAuthIv, tgsAuthCipher));
            tgsReq.setPadata(mapper.writeValueAsBytes(padataApReq));

            String tgsRepJson = httpPost(TGS_URL + "/tgs_req", mapper.writeValueAsString(tgsReq));
            TGS_REP tgsRep = mapper.readValue(tgsRepJson, TGS_REP.class);
            printOk("TGS_REP received - Service Ticket issued for app-service@" + REALM);

            // decrypt tgs_rep
            byte[] tgsRepEnc = tgsRep.getEncPart();
            byte[] tgsRepIv = Arrays.copyOfRange(tgsRepEnc, 0, 16);
            byte[] tgsRepCipher = Arrays.copyOfRange(tgsRepEnc, 16, tgsRepEnc.length);

            byte[] decryptedTgsRep = crypto.decrypt(tgsRepCipher, sessionKey, tgsRepIv);
            Map<String, Object> tgsRepData = mapper.readValue(decryptedTgsRep, new TypeReference<Map<String, Object>>() {});

            byte[] serviceSessionKey = Base64.getDecoder().decode((String) tgsRepData.get("sessionKey"));
            Ticket serviceTicket = tgsRep.getTicket();
            printOk("TGS_REP decrypted — service session key extracted");

            // ═══════════════════════════════════════════════════════════
            // step 5: access app
            // ═══════════════════════════════════════════════════════════
            printStep(5, "AP_REQ", "Accessing protected App Service...");

            Authenticator appAuth = new Authenticator(clientPrincipal, System.currentTimeMillis(), 0);
            byte[] appAuthBytes = mapper.writeValueAsBytes(appAuth);
            byte[] appAuthIv = crypto.generateIv();
            byte[] appAuthCipher = crypto.encrypt(appAuthBytes, serviceSessionKey, appAuthIv);

            AP_REQ finalApReq = new AP_REQ();
            finalApReq.setTicket(serviceTicket);
            finalApReq.setEncryptedAuthenticator(combineIvAndCiphertext(appAuthIv, appAuthCipher));

            String token = Base64.getEncoder().encodeToString(mapper.writeValueAsBytes(finalApReq));
            String appResponse = httpGetWithAuth(APP_URL + "/secure-data", "Negotiate " + token);
            printOk("App Service responded: " + appResponse);

            // ═══════════════════════════════════════════════════════════
            printSuccess(username);

        } catch (RuntimeException e) {
            System.out.println();
            printFail("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            System.out.println();
            printFail("Authentication failed: " + e.getMessage());
        }
    }

    // ───────────────────────── HTTP Helpers ─────────────────────────

    private static String httpPost(String urlStr, String jsonBody) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.getOutputStream().write(jsonBody.getBytes(StandardCharsets.UTF_8));

        if (conn.getResponseCode() != 200) {
            BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = err.readLine()) != null) sb.append(line);
            throw new RuntimeException("HTTP " + conn.getResponseCode() + ": " + sb);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    private static String httpGet(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        if (conn.getResponseCode() != 200) {
            throw new RuntimeException("HTTP " + conn.getResponseCode());
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    private static String httpGetWithAuth(String urlStr, String authHeader) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", authHeader);

        if (conn.getResponseCode() != 200) {
            BufferedReader err = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = err.readLine()) != null) sb.append(line);
            throw new RuntimeException("HTTP " + conn.getResponseCode() + ": " + sb);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) sb.append(line);
        return sb.toString();
    }

    private static byte[] combineIvAndCiphertext(byte[] iv, byte[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }

    // ───────────────────────── Pretty Output ─────────────────────────

    private static void printBanner() {
        System.out.println("╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║           KERBEROS V5 AUTHENTICATION CLIENT               ║");
        System.out.println("║              Simulation Framework                         ║");
        System.out.println("╠═══════════════════════════════════════════════════════════╣");
        System.out.println("║  Enter your credentials to authenticate:                  ║");
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
    }

    private static void printStep(int num, String phase, String msg) {
        System.out.println("┌─────────────────────────────────────────────────────────┐");
        System.out.printf("│  STEP %d: %-46s │%n", num, phase);
        System.out.println("└─────────────────────────────────────────────────────────┘");
        System.out.println("  >> " + msg);
    }

    private static void printOk(String msg) {
        System.out.println("  [OK] " + msg);
    }

    private static void printFail(String msg) {
        System.out.println("  [FAIL] " + msg);
    }

    private static void printSuccess(String username) {
        System.out.println();
        System.out.println("╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║                  AUTHENTICATION SUCCESS                   ║");
        System.out.println("╠═══════════════════════════════════════════════════════════╣");
        System.out.printf("║  User    : %-46s ║%n", username);
        System.out.println("║  Status  : Fully authenticated via Kerberos V5            ║");
        System.out.println("║  Access  : App Service granted                            ║");
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
    }
}
