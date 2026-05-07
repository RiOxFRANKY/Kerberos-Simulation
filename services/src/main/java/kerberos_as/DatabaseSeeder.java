package kerberos_as;

import crypto.AesCryptoService;
import crypto.CryptoOperations;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.transaction.Transactional;
import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Seeds the KDC Principal Database on startup by loading users from
 * 100_users.csv (bundled in the classpath). Also seeds the app-service
 * service account. Passwords are hashed using PBKDF2 (310,000 iterations)
 * before being persisted — plaintext is never stored.
 *
 * Skips any principal that already exists, making this safe to run
 * on every restart.
 */
@ApplicationScoped
public class DatabaseSeeder {

    private static final Logger LOG = Logger.getLogger(DatabaseSeeder.class);

    private final CryptoOperations crypto = new AesCryptoService();

    @Transactional
    void onStart(@Observes StartupEvent event) {
        LOG.info("=== KDC Database Seeder: loading principals ===");

        // Seed the app-service service account (required for ticket issuance)
        seedPrincipal("app-service", "appSvc!S3cretK3y");

        // Load user accounts from CSV
        loadUsersFromCsv("100_users.csv");

        long totalPrincipals = PrincipalEntity.count();
        LOG.infof("=== KDC Database Seeder: complete — %d principals in database ===", totalPrincipals);
    }

    private void loadUsersFromCsv(String resourceName) {
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) {
                LOG.warnf("CSV file '%s' not found on classpath — skipping CSV import", resourceName);
                return;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            int created = 0;
            int skipped = 0;
            boolean isHeader = true;

            while ((line = reader.readLine()) != null) {
                // Skip header row
                if (isHeader) {
                    isHeader = false;
                    continue;
                }

                line = line.trim();
                if (line.isEmpty()) continue;

                String[] parts = line.split(",", 2);
                if (parts.length < 2) {
                    LOG.warnf("  [SKIP] Malformed CSV line: %s", line);
                    continue;
                }

                String username = parts[0].trim();
                String password = parts[1].trim();

                if (PrincipalEntity.findByUsername(username) != null) {
                    skipped++;
                    continue;
                }

                seedPrincipalQuiet(username, password);
                created++;
            }

            LOG.infof("  [CSV] Processed %s — created: %d, skipped (existing): %d",
                    resourceName, created, skipped);

        } catch (Exception e) {
            LOG.errorf(e, "  [ERROR] Failed to load CSV '%s'", resourceName);
        }
    }

    private void seedPrincipal(String username, String password) {
        try {
            if (PrincipalEntity.findByUsername(username) != null) {
                LOG.infof("  [SKIP] Principal '%s' already exists", username);
                return;
            }
            seedPrincipalQuiet(username, password);
            LOG.infof("  [CREATED] Principal '%s' registered with PBKDF2 hash", username);
        } catch (Exception e) {
            LOG.errorf(e, "  [ERROR] Failed to seed principal '%s'", username);
        }
    }

    private void seedPrincipalQuiet(String username, String password) throws Exception {
        byte[] salt = crypto.generateSalt();
        byte[] derivedKey = crypto.deriveKey(password, salt);

        PrincipalEntity principal = new PrincipalEntity();
        principal.username = username;
        principal.passwordHash = Base64.getEncoder().encodeToString(derivedKey);
        principal.salt = Base64.getEncoder().encodeToString(salt);
        principal.persist();
    }
}
