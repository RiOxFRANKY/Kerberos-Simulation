# 🔐 Kerberos V5 Authentication Protocol Simulation Framework

Welcome to the **Kerberos V5 Simulation Framework**! This repository provides a highly-detailed, containerized, and fully functional simulation of the MIT Kerberos V5 authentication protocol. 

It is specifically designed for DevSecOps engineers, security researchers, and developers who want to understand the intricate cryptographic handshakes, stateless ticket management, and Zero-Trust network architecture concepts that make Kerberos the gold standard for enterprise authentication.

---

## 🚀 1. Getting Started & System Requirements

If you want to run this simulation on your own PC, you will need the following dependencies installed:

### Prerequisites
1. **Docker Desktop**: With **Kubernetes enabled** in the settings. This acts as the local cluster.
2. **Terraform**: To provision the Kubernetes resources automatically.
3. **Java 17+**: Required to compile the microservices and run the CLI client.
4. **Apache Maven**: To manage dependencies and build the Java code.
5. **Git**: To clone the repository.

### Initial Setup (First-Time Run)

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd Kerberos-Simulation
   ```

2. **Build the Microservices & Docker Images:**
   Before Terraform can deploy the containers to Kubernetes, you must compile the Java code and build the local Docker images.
   ```bash
   cd services
   mvn clean package -DskipTests -Dnet.bytebuddy.experimental=true
   cd ..
   docker compose build
   ```

3. **Deploy the Infrastructure via Terraform:**
   With the images built, instruct Terraform to provision the Kubernetes pods, services, databases, and secrets.
   ```bash
   terraform init
   terraform apply -auto-approve
   ```
   *(Note: This step may take a minute as PostgreSQL and Redis initialize).*

4. **Verify Deployment:**
   Ensure all 5 pods (AS, TGS, App Service, Postgres, Redis) are in the `Running` state:
   ```bash
   kubectl get pods
   ```

---

## 🏗️ 2. Technical Architecture & Component Breakdown

The infrastructure mimics a real-world enterprise network, utilizing microservices for strict isolation and security.

### Core Services
| Component | Port | Technology | Purpose |
| :--- | :--- | :--- | :--- |
| **Authentication Server (AS)** | `8081` | Java / Quarkus | The front door of the Key Distribution Center (KDC). Verifies user credentials and issues the **Ticket Granting Ticket (TGT)**. Enforces Pre-Authentication. |
| **Ticket Granting Server (TGS)** | `8082` | Java / Quarkus | Validates TGTs and issues **Service Tickets** for specific target applications. |
| **App Service** | `8083` | Java / Quarkus | The highly-secure target application. Validates Service Tickets and grants access to protected resources. |

### Data Persistence Layer
| Component | Port | Technology | Purpose |
| :--- | :--- | :--- | :--- |
| **KDC Database** | `5432` | PostgreSQL 16 | The highly-secured ledger. Stores encrypted long-term keys, user credentials, and service principals. |
| **KDC Store** | `6379` | Redis 7.2 | Acts as an ultra-fast caching layer for managing active authentication nonces, replay-attack prevention, and transient session data. |

---

## 🛡️ 3. The Kerberos V5 Cryptographic Flow

The standalone Java CLI Client (`KerberosCliClient.java`) simulates an end-user interacting with the network. Here is exactly what happens cryptographically when you execute it:

### Phase 1: Pre-Authentication & Key Derivation
- The client requests a cryptographic salt from the **AS**.
- Using the salt and the user's password, the client locally derives a 256-bit long-term **AES Key** via the `PBKDF2WithHmacSHA256` algorithm (running at 310,000 iterations to prevent brute-force attacks). The actual password **never** leaves the client machine.

### Phase 2: AS Exchange (Getting the TGT)
- **Pre-Authentication (`PA-ENC-TIMESTAMP`)**: Before the AS will issue a Ticket Granting Ticket (TGT), the client must prove it knows the password. It encrypts the current timestamp using its derived AES key and sends this in the `AS_REQ`.
- **AS_REQ**: The client sends the plaintext request containing their principal name, a random nonce, and the Pre-Auth padata.
- **AS_REP**: The AS decrypts the Pre-Auth data. If the timestamp is valid, it verifies the user. The AS then generates a **Session Key**, and creates the **TGT**. The AS encrypts the Session Key with the user's long-term AES key and encrypts the TGT with the KDC's master key. The client decrypts the payload to retrieve the Session Key.

### Phase 3: TGS Exchange (Getting the Service Ticket)
- **TGS_REQ**: The client wants to talk to the `app-service`. It builds an **Authenticator** (containing a timestamp to prevent replay attacks), encrypts it with the Session Key, and sends it to the TGS along with the TGT.
- **TGS_REP**: The TGS decrypts the TGT (using the KDC master key), verifies the Authenticator against its Redis Replay Cache, and issues a **Service Ticket**. This ticket is encrypted using the App Service's long-term key.

### Phase 4: AP Exchange (Accessing the App)
- **AP_REQ**: The client sends the Service Ticket and a fresh Authenticator to the App Service.
- **Authorization**: The App Service decrypts the Service Ticket using its own private key, extracts the Service Session Key, and uses it to decrypt the Authenticator. 
- **Validation**: The App Service verifies the timestamp against its own Redis Replay Cache. If valid and unseen, access to the highly classified data is granted!

---

## 🛑 4. Security Audits & Vulnerability Remediation

This codebase intentionally highlights how cryptographic systems can fail if implemented incorrectly. We have actively patched two major, real-world vulnerabilities in this simulation:

### A. Defeating AS-REP Roasting (Offline Dictionary Attacks)
**The Flaw:** Initially, the Authentication Server would issue an encrypted TGT to anyone who asked for a specific username. An attacker could anonymously request a TGT, download the encrypted blob, and use tools like Hashcat offline to guess the user's password millions of times a second without triggering alarms.
**The Patch:** We implemented `PA-ENC-TIMESTAMP` Pre-Authentication. Now, the AS strictly refuses to issue a TGT unless the initial request packet includes a timestamp encrypted by the user's actual password. Offline brute-forcing is mathematically neutralized.

### B. Defeating Replay Attacks on the App Service
**The Flaw:** The `app-service` verified that incoming Service Tickets were valid within a 5-minute skew, but it did not maintain a state of "used" tickets. A network eavesdropper could capture a valid `AP_REQ` packet and endlessly replay it to the App Service within that 5-minute window to steal data.
**The Patch:** We integrated the `kdc-store` Redis caching layer directly into the App Service. When a ticket is used, its unique signature (`replay:app:username:timestamp`) is recorded in Redis via an atomic `SETNX` command. Replayed packets are instantly rejected with a `401 Unauthorized`.

---

## 🚀 5. Infrastructure as Code (Terraform & Local Kubernetes)

The entire infrastructure is defined as code and deployed to your local Docker Desktop Kubernetes cluster. We utilize the `gavinbunney/kubectl` Terraform provider to directly orchestrate Kubernetes YAML manifests (`k8s/base/`) without any AWS vendor lock-in.

### Detailed Deployment Steps
1. **Initialize the Terraform Environment:**
   Downloads the required providers and initializes the local state file (`.terraform/`).
   ```bash
   terraform init
   ```
2. **Review the Infrastructure Plan:**
   Shows exactly which Kubernetes Services, Deployments, and Secrets will be created.
   ```bash
   terraform plan
   ```
3. **Provision the Cluster:**
   Applies the manifests to your cluster.
   ```bash
   terraform apply -auto-approve
   ```

Because the services are configured as `LoadBalancer`, Docker Desktop automatically maps the ports (`8081`, `8082`, `8083`) to your local machine.

### Modifying and Re-Deploying Code
If you edit the underlying Java source code, you must re-bake the Docker images and cycle the pods:
```bash
# 1. Recompile Java Code
cd services
mvn clean package -DskipTests -Dnet.bytebuddy.experimental=true
cd ..

# 2. Rebuild the Local Docker Images
docker compose build

# 3. Force Kubernetes to pull the new images
kubectl rollout restart deployment kerberos-as kerberos-tgs app-service
```

### Teardown
To cleanly destroy the entire Kubernetes cluster and remove all state:
```bash
terraform destroy -auto-approve
```

---

## 🏃 6. Running the Client Simulation

Once your Kubernetes pods are running (`kubectl get pods`), you can launch the interactive Java CLI to watch the cryptographic exchange in real time.

1. Navigate to the `services` directory.
2. Run the CLI:
   ```bash
   cd services
   mvn clean compile exec:java "-Dexec.mainClass=kerberos_client.KerberosCliClient"
   ```

You will be prompted for credentials. The KDC database is seeded with 100 test accounts on startup. 
* **Example Valid User:** Username: `EchoKnight549` / Password: `Phantom1214%`

The client will print out real-time logs of the AS, TGS, and AP cryptographic exchanges!

---

## 📈 7. Observability & Monitoring (Prometheus & Grafana)

In a production Zero-Trust environment, monitoring authentication flows is critical. 
- **Prometheus** acts as the data scraper, pulling time-series metrics from the Quarkus endpoints (`/q/metrics`). It tracks latency, throughput, and error rates (e.g., failed PBKDF2 decryption attempts).
- **Grafana** connects to Prometheus to provide a visual "single pane of glass", allowing DevSecOps teams to set up alerts for brute-force attacks, DDoS attempts on the Authentication Server, and abnormal ticket-granting spikes.

---

## 🔐 8. DevSecOps & CI/CD Pipeline

This repository enforces strict security and quality checks via GitHub Actions (`.github/workflows/devsecops-pipeline.yml`). 

Every Pull Request and Push to `main` triggers:
1. **Maven Unit Testing**: Verifies cryptographic integrity and protocol logic.
2. **Static Application Security Testing (SAST)**: Uses Semgrep to scan raw Java code for hardcoded secrets or vulnerable code patterns.
3. **Dependency Vulnerability Scanning**: Uses Trivy to scan the compiled Docker Containers for unpatched CVEs in base images (like Alpine) or Java libraries (like Jackson). If a `CRITICAL` vulnerability is found, the pipeline forcefully halts.
4. **Terraform End-to-End Testing**: Spins up a temporary KinD (Kubernetes in Docker) cluster within the GitHub Actions runner, executes `terraform apply`, and ensures the infrastructure is valid before allowing the code to be merged.

---

## 📁 9. Repository Structure

```text
.
├── docker/
│   └── Dockerfile.jvm           # Multi-stage Dockerfile for all Quarkus microservices
├── k8s/
│   └── base/                    # Raw Kubernetes YAML manifests (Deployments, Services, Secrets)
├── services/
│   ├── src/main/java/           # Java Source Code
│   │   ├── app_service/         # The Target Application (ProtectedResource)
│   │   ├── kerberos_as/         # Authentication Server (AuthResource, DatabaseSeeder)
│   │   ├── kerberos_tgs/        # Ticket Granting Server (TgsResource)
│   │   ├── kerberos_client/     # The CLI Client Simulation
│   │   └── kerberos_core/       # Shared Crypto Logic & Data Models (AS_REQ, TGS_REQ)
│   ├── src/main/resources/      
│   │   └── 100_users.csv        # Database seeding file
│   └── pom.xml                  # Maven dependencies configuration
├── terraform/
│   ├── environments/dev/        # Environment-specific configuration
│   └── modules/k8s-local/       # Reusable Terraform logic for applying manifests
├── main.tf                      # Root Terraform execution point
├── docker-compose.yml           # Local Image builder
└── README.md                    # You are here
```
