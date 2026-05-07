# Project Information & Architecture Details

This document provides an exhaustive explanation of the theoretical concepts, frameworks, and deployment strategies utilized in this Kerberos V5 Simulation project.

---

## 1. Cryptographic Foundations of the Simulation

At the heart of the Kerberos protocol lies its complete reliance on symmetric-key cryptography. Unlike public-key infrastructure (PKI) which uses asymmetric key pairs (public/private keys), symmetric cryptography requires both the encrypting and decrypting parties to possess the exact same secret key. In this simulation, we have implemented industry-standard cryptographic algorithms using the Java Cryptography Architecture (JCA) to ensure the highest level of data confidentiality and integrity.

**Advanced Encryption Standard (AES-256)**
All tickets, authenticators, and session keys transmitted across the network are encrypted using AES (Advanced Encryption Standard) with a 256-bit key size. AES-256 is currently considered military-grade encryption and is mathematically infeasible to brute-force with modern computing power. Specifically, the simulation employs `AES/GCM/NoPadding`. Galois/Counter Mode (GCM) ensures both confidentiality and cryptographic integrity, completely neutralizing Padding Oracle attacks (a common vulnerability in older CBC modes). Before any payload is encrypted, our `AesCryptoService` generates a mathematically random 16-byte IV using `SecureRandom`. This IV is prepended to the ciphertext and sent across the wire, ensuring cryptographic unpredictability.

**Password-Based Key Derivation Function 2 (PBKDF2)**
In Kerberos, the user's password acts as the foundation for their identity. However, storing raw passwords or even simple hashes (like MD5 or SHA-256) is highly insecure due to the threat of rainbow tables and GPU-accelerated dictionary attacks. To mitigate this, our Key Distribution Center (KDC) utilizes `PBKDF2WithHmacSHA256`. When a user's password is created, the system generates a unique cryptographic "salt"—a random string of data. The password and the salt are fed into the PBKDF2 algorithm, which hashes the combination 310,000 times. This intentionally slows down the key derivation process. For a legitimate user logging in once, the delay of a few milliseconds is imperceptible. But for an attacker attempting to guess millions of passwords a second, this computational overhead makes brute-forcing mathematically impossible within a human lifetime. The output of this function is the 256-bit long-term AES key used to encrypt the user's tickets.

**Nonces and Replay Protection**
Cryptography isn't just about hiding data; it's also about preventing data manipulation. A common threat in network security is a "Replay Attack," where an adversary captures a securely encrypted packet (like a login request) and simply resends it to trick the server into granting access. To prevent this, the Kerberos cryptography relies heavily on "Nonces" (Numbers Used Once) and timestamps. When the client initiates a request, it generates a random 64-bit long integer (the nonce). The server must include this exact nonce inside its encrypted reply. If the client decrypts the reply and the nonce doesn't match, it instantly knows the packet was tampered with or delayed by a Man-in-the-Middle (MitM) attacker. Furthermore, all Authenticators include a millisecond-precision timestamp. If an attacker captures an Authenticator and replays it, the server checks its Redis cache. Since the timestamp has already been recorded, the cryptographic packet is rejected as a duplicate, preserving the integrity of the session.

---

## 2. How the Kerberos Protocol Works

Kerberos is a computer network authentication protocol that works on the basis of "tickets" to allow nodes communicating over a non-secure network to prove their identity to one another in a highly secure manner. Its name is derived from the three-headed dog of Greek mythology, symbolizing the protocol's three primary components: the Client, the Key Distribution Center (KDC), and the Application Server. The KDC itself is logically divided into two parts: the Authentication Server (AS) and the Ticket Granting Server (TGS).

The fundamental philosophy of Kerberos is that passwords should never be sent across the network. Instead, the protocol relies on symmetric-key cryptography to securely exchange identity assertions. The workflow consists of four distinct phases:

**Phase 1: Pre-Authentication**
To prevent offline dictionary attacks, the protocol requires Pre-Authentication. When a user wishes to authenticate, their local machine prompts them for a password. The machine passes this password through a key derivation function (like PBKDF2) to generate a cryptographic key. The client then takes the current timestamp, encrypts it using this key, and sends it to the Authentication Server as part of the initial request (AS_REQ). 

**Phase 2: Authentication Server (AS) Exchange**
The AS receives the request and looks up the user in its secure database to retrieve the user's hashed key. It attempts to decrypt the timestamp. If successful, it proves the user entered the correct password. The AS then generates a random "Session Key" for the client to use. It packages this session key into two forms: one encrypted with the user's password-derived key (so the client can read it), and one embedded inside a Ticket Granting Ticket (TGT). Crucially, the TGT is encrypted using the KDC's Master Key—a secret known only to the KDC. The client receives this payload, decrypts their portion to get the session key, and holds onto the opaque TGT.

**Phase 3: Ticket Granting Server (TGS) Exchange**
Now the client possesses a TGT, which acts like a passport. However, to access a specific service (like an email server or an internal web app), they need a specific visa: a Service Ticket. The client sends a TGS_REQ containing the TGT, the name of the service they want, and an "Authenticator" (a fresh timestamp encrypted with their session key). The TGS uses the KDC Master Key to decrypt the TGT. It extracts the session key and uses it to decrypt the Authenticator. If the timestamp is valid and hasn't been seen before, the TGS knows the request is legitimate. It then creates a Service Ticket, encrypts it with the target service's long-term key, and sends it back to the client.

**Phase 4: Application Server (AP) Exchange**
Finally, the client approaches the target Application Server. They send an AP_REQ containing the Service Ticket and a newly generated Authenticator. The Application Server decrypts the Service Ticket using its own private key, extracts the Service Session Key, and uses that to decrypt the Authenticator. The Application Server checks its own internal Replay Cache to ensure the timestamp hasn't been submitted previously. If everything aligns, the server grants access to the requested resources. Through this entire dance, the user's actual password never traversed the network.

---

## 3. How the Quarkus API Implemented Kerberos

In this project, the Kerberos protocol is simulated using Quarkus, a modern, Kubernetes-native Java framework tailored for GraalVM and HotSpot. Quarkus was chosen because of its incredibly fast boot times and low memory footprint, making it ideal for microservices architecture. The simulation maps the Kerberos entities into distinct RESTful microservices.

**The Authentication Server (AS)**
Implemented in `AuthResource.java`, the AS acts as the gateway. We utilized Quarkus Hibernate ORM with Panache to connect to a highly-secured PostgreSQL database. This database stores the `PrincipalEntity`, which contains the usernames and their PBKDF2 hashed long-term keys. When a request hits the `/as_req` endpoint, Quarkus intercepts it and processes the JSON payload. We implemented raw Java Cryptography Architecture (JCA) using `AES/GCM/NoPadding` to simulate the encryption layers. The AS explicitly extracts the `padata` (pre-authentication data), decrypts it using the user's database key, and validates the timestamp. Upon success, it uses Jackson ObjectMapper to serialize the Ticket Granting Ticket (TGT) and encrypts it using the KDC Master Key injected directly from Kubernetes secrets via MicroProfile Config (`@ConfigProperty`).

**The Ticket Granting Server (TGS)**
Implemented in `TgsResource.java`, the TGS is responsible for issuing Service Tickets. A significant challenge in Kerberos is preventing replay attacks. If an attacker intercepts the TGS_REQ, they could repeatedly send it. To mitigate this, our Quarkus TGS integrates the `quarkus-redis-client`. When an Authenticator is decrypted, the TGS connects to the `kdc-store` Redis instance. It constructs a unique Redis key combining the user's principal name and the timestamp. Using the atomic `SETNX` (Set if Not eXists) command, it verifies whether this specific packet has been processed within the last 5 minutes. If Redis returns false, Quarkus immediately aborts the transaction with a `401 Unauthorized` response. If successful, it generates the Service Ticket and encrypts it with the target Application Service's key.

**The Application Service**
Implemented in `ProtectedResource.java`, this microservice represents the final destination for the client. Just like the TGS, it relies heavily on the Quarkus Redis extension to validate incoming `AP_REQ` payloads. It decrypts the Service Ticket using its injected `APP_SERVICE_KEY`. After verifying the Authenticator against its own Replay Cache, it authorizes the transaction and returns the protected JSON payload.

**The Client Simulation**
The `KerberosCliClient.java` acts as the user's terminal. It leverages Quarkus's RESTEasy client libraries to issue HTTP requests to the AS, TGS, and App Service. It handles the complex orchestration of generating local nonces, executing the 310,000 PBKDF2 iterations for key derivation, nesting encrypted Authenticators inside JSON payloads, and unrolling the nested encryption layers returned by the KDC.

---

## 4. The Use of Docker in This Project

Docker is utilized as the foundational containerization engine for this project, serving the critical purpose of ensuring environmental consistency and isolating dependencies. 

By defining the infrastructure in a `docker/Dockerfile.jvm`, we eliminate the classic "it works on my machine" problem. The Dockerfile uses a multi-stage approach, leveraging a robust Maven image to compile the Quarkus microservices and download dependencies in a reproducible manner. It then packages only the compiled `fast-jar` artifacts into a lightweight `eclipse-temurin:17-jre-alpine` runtime image. This dramatically reduces the attack surface and image size, making it ideal for DevSecOps environments.

Furthermore, Docker abstracts away complex infrastructure dependencies. Instead of requiring developers to manually install, configure, and secure PostgreSQL 16 and Redis 7.2 on their local workstations, Docker pulls official, pre-configured images. The `docker-compose.yml` file originally bound these isolated containers together into a unified virtual network, allowing the Kerberos microservices to communicate with the databases seamlessly. In the final architecture, these Docker images become the standard artifacts that Kubernetes consumes, ensuring that the exact same binary code tested by developers is what ultimately runs in production.

---

## 5. The Use of Kubernetes in This Project

While Docker packages the application, Kubernetes acts as the orchestra conductor, managing the deployment, scaling, and operational lifecycle of the Kerberos simulation. We migrated the project to a local Kubernetes cluster (running via Docker Desktop) to simulate a true enterprise-grade distributed environment.

**High Availability and Self-Healing**
Kubernetes `Deployments` are utilized for the stateless microservices: the Authentication Server, Ticket Granting Server, and App Service. By defining replicas, Kubernetes ensures that if a Java process crashes or a node fails, it automatically spins up a replacement pod to maintain availability. 

**Stateful Management**
For the KDC Database (PostgreSQL), we utilize a `StatefulSet`. Unlike standard deployments, StatefulSets provide stable, unique network identifiers and persistent storage guarantees, which is absolutely critical for a database holding cryptographic keys. If the database pod goes down, Kubernetes ensures it reconnects to the exact same persistent volume upon restart.

**Networking and Service Discovery**
Kubernetes `Services` provide an internal DNS resolution layer. The Kerberos microservices do not rely on hardcoded IP addresses; instead, they communicate using logical DNS names (e.g., `http://kdc-db:5432`). We utilize `LoadBalancer` services to expose the AS, TGS, and App Service to the host machine, allowing the local Java CLI client to interact with the cluster seamlessly.

**Secure Secret Management**
Perhaps most importantly for a security protocol, Kubernetes `Secrets` are employed. Instead of hardcoding the KDC Master Key or Database passwords in the source code or plain-text environment variables, they are stored securely in the cluster as Opaque secrets (`kerberos-secrets`). These secrets are injected into the Quarkus pods at runtime, ensuring that sensitive cryptographic material remains decoupled from the application logic.

---

## 6. The Use of Terraform in This Project

Terraform is utilized to provide Infrastructure as Code (IaC), replacing manual `kubectl` commands with a predictable, version-controlled, and automated deployment strategy.

Initially, the project was designed to deploy to AWS Elastic Kubernetes Service (EKS). However, to avoid vendor lock-in and enable rapid local development, the Terraform configuration was refactored to target the local Kubernetes cluster. This was achieved using the `gavinbunney/kubectl` provider.

**Declarative Orchestration**
Instead of writing complex HashiCorp Configuration Language (HCL) to translate Kubernetes APIs, the Terraform module is configured to read the raw YAML manifests directly from the `k8s/base/` directory. Terraform calculates the desired state of all 12 resources (Deployments, Services, Secrets, and StatefulSets) and determines the exact sequence of API calls required to provision them.

**Dependency Management and Auditing**
When executing `terraform plan`, developers are presented with a deterministic, auditable execution plan showing exactly what infrastructure will be created, modified, or destroyed. When `terraform apply` is executed, Terraform manages the state of the cluster in a local `.tfstate` file. If a developer accidentally deletes a service via the CLI, the next Terraform run will instantly detect the drift and recreate it.

**Clean Teardown**
In complex microservice environments, cleaning up resources can be error-prone, leaving orphaned volumes or secrets behind. Terraform simplifies this entirely. A single `terraform destroy` command elegantly tears down the entire simulation environment in the correct dependency order, ensuring no persistent artifacts or running containers clutter the local machine.

---

## 7. How DevSecOps is Implemented in This Project

DevSecOps—the integration of security practices directly into the DevOps workflow—is fundamentally baked into this project via an automated GitHub Actions pipeline (`devsecops-pipeline.yml`). This pipeline enforces a "shift-left" security mentality, catching vulnerabilities before they can ever be deployed.

**Continuous Integration and Testing**
The pipeline triggers automatically on every push or Pull Request to the `main` branch. The first gate is the `build-and-test` job. It spins up an ephemeral Ubuntu runner, configures the JDK, and executes Maven Unit Tests. This ensures that any modifications to the cryptographic logic (such as AES padding changes or PBKDF2 iterations) do not break the strict mathematical requirements of the Kerberos protocol.

**Static Application Security Testing (SAST)**
Once tests pass, the code undergoes a SAST scan using **Semgrep**. Semgrep analyzes the raw Java syntax against predefined security rulesets. If a developer accidentally hardcodes a database password, uses a weak hashing algorithm (like MD5), or commits a predictable random number generator instead of `SecureRandom`, Semgrep instantly fails the pipeline, preventing the insecure code from merging.

**Container Vulnerability Scanning**
The pipeline then builds the multi-stage Docker containers. Before these containers are cleared for deployment, they are deeply analyzed by **Trivy**, an industry-standard container security scanner. Trivy inspects the base OS (Alpine) and all Java dependencies (like Jackson or Hibernate) for known Common Vulnerabilities and Exposures (CVEs). We enforce a strict failure threshold: if a `CRITICAL` vulnerability (like Log4Shell) is detected, the job crashes, physically blocking the deployment of vulnerable infrastructure.

**Automated Infrastructure Testing**
Finally, the pipeline validates the Terraform IaC. Because the GitHub Actions runner doesn't have Docker Desktop installed, the pipeline dynamically provisions a KinD (Kubernetes in Docker) cluster. It runs `terraform init` and `terraform apply` against this ephemeral cluster. This end-to-end deployment test guarantees that the infrastructure code is syntactically valid and deployable, serving as the ultimate quality gate before releasing the code to a production environment.

---

## 8. Real-World Example Scenario: Corporate Single Sign-On (SSO)

To truly understand the value of Kerberos, it is best to visualize how it operates in a modern corporate environment utilizing Single Sign-On (SSO). Imagine a scenario where a new employee, Alice, arrives for her first day at a large enterprise. 

When Alice boots up her corporate laptop, she is presented with a standard Windows or Linux login screen. She enters her username (`alice`) and her highly secure password. Behind the scenes, her laptop takes this password and silently executes the Kerberos Pre-Authentication flow against the company's Active Directory (which acts as the Kerberos Key Distribution Center). The KDC verifies her credentials and securely issues her a Ticket Granting Ticket (TGT). Her laptop stores this TGT securely in memory. This is the **only** time Alice will have to type her password today.

An hour later, Alice needs to access the company's internal Human Resources portal to enroll in health benefits. The HR portal is a highly sensitive web application that requires strict authorization. Instead of prompting Alice for her password again, her web browser silently requests a Service Ticket for the HR portal from the Ticket Granting Server using her cached TGT. The TGS validates her TGT, checks her permissions, and issues the Service Ticket.

Alice's browser then seamlessly forwards this Service Ticket to the HR web server via an HTTP header (often using SPNEGO/Negotiate protocols). The HR server decrypts the ticket using its own private key, cryptographically verifying that Alice is exactly who she claims to be and that the KDC has vouched for her. The HR portal immediately logs her in, displaying her employee dashboard. 

Later in the afternoon, Alice attempts to connect to a secure corporate file share via SMB, and then opens her internal email client. In both instances, the exact same invisible handshake occurs. The TGS issues Service Tickets for the File Server and the Exchange Server, which are presented to the respective applications. Throughout the entire day, spanning dozens of different applications and microservices, Alice's password never once traveled across the network, completely neutralizing the threat of password-sniffing malware or rogue network administrators. This seamless, stateless, and cryptographically bulletproof experience is the definitive power of the Kerberos protocol.
