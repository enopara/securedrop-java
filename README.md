# SecureDrop

SecureDrop is a Java Spring Boot network security project that demonstrates a hybrid encryption workflow for secure text-message delivery.

The default implementation is secure by design for this class demo:

- Passwords are hashed with BCrypt.
- Each user receives an RSA-3072 keypair during registration.
- Public keys are stored as PEM text.
- Private keys are encrypted before database storage.
- Messages are encrypted with AES-GCM.
- AES message keys are wrapped with recipient RSA-OAEP public keys.
- JWT protects package endpoints after login.

The project also includes controlled crypto mistake modes for professor feedback experiments.

## Stack

- Java 21
- Spring Boot
- Maven
- MySQL 8 in Docker
- Spring Data JPA
- Spring Security
- JWT

## Project Status

Completed backend phases:

- Service layer registration, send, and read flow
- REST controllers/endpoints
- Minimal JWT authentication
- Crypto experiment toggles

No frontend is included yet.

## Important Paths

```text
src/main/java/com/emmanuel/securedrop/domain
src/main/java/com/emmanuel/securedrop/repository
src/main/java/com/emmanuel/securedrop/service
src/main/java/com/emmanuel/securedrop/web
src/main/java/com/emmanuel/securedrop/security
src/main/java/com/emmanuel/securedrop/crypto
src/main/resources/application.properties
src/test/java/com/emmanuel/securedrop
docker-compose.yml
```

## Run Locally

Start MySQL:

```powershell
docker compose up -d
```

Run tests:

```powershell
mvn test
```

Start the application:

```powershell
mvn spring-boot:run
```

The API runs at:

```text
http://localhost:8080
```

MySQL is exposed on:

```text
localhost:3307
```

Workbench connection:

```text
Host: localhost
Port: 3307
Database: securedrop
Username: securedrop_user
Password: securedrop_pass
```

## API Demo

If the users already exist, either log in with them or choose new usernames/emails.

### Register Alice

```powershell
$aliceRegister = @{
  username="alice"
  email="alice@example.com"
  password="alicePassword1!"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/auth/register `
  -ContentType "application/json" `
  -Body $aliceRegister
```

Expected: returns Alice's id, username, email, and public key PEM. It does not return the password hash or encrypted private key.

### Register Bob

```powershell
$bobRegister = @{
  username="bob"
  email="bob@example.com"
  password="bobPassword1!"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/auth/register `
  -ContentType "application/json" `
  -Body $bobRegister
```

### Login Alice

```powershell
$aliceLogin = @{
  username="alice"
  password="alicePassword1!"
} | ConvertTo-Json

$alice = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body $aliceLogin

$aliceToken = $alice.token
```

Expected: returns a JWT token.

### Send A Secure Message From Alice To Bob

```powershell
$message = @{
  recipientUsername="bob"
  message="Secret demo message"
} | ConvertTo-Json

$package = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/packages/send `
  -ContentType "application/json" `
  -Headers @{ Authorization="Bearer $aliceToken" } `
  -Body $message

$package
```

Expected: returns a package id, sender, recipient, timestamp, and `cryptoMode`.

### Login Bob

```powershell
$bobLogin = @{
  username="bob"
  password="bobPassword1!"
} | ConvertTo-Json

$bob = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/auth/login `
  -ContentType "application/json" `
  -Body $bobLogin

$bobToken = $bob.token
```

### View Bob's Inbox

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri http://localhost:8080/packages/inbox/bob `
  -Headers @{ Authorization="Bearer $bobToken" }
```

### Read And Decrypt The Package

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:8080/packages/$($package.id)" `
  -Headers @{
    Authorization="Bearer $bobToken"
    "X-Demo-Password"="bobPassword1!"
  }
```

Expected: returns the plaintext message.

The JWT proves that the caller is Bob. `X-Demo-Password` is still required because Bob's password decrypts Bob's encrypted private RSA key.

## Secure Storage Notes

For this class project:

- Passwords are stored as BCrypt hashes.
- Public RSA keys are stored in the database as PEM.
- Private RSA keys are encrypted using password-derived AES-GCM before storage.
- Package plaintext is never stored.
- AES message keys are never stored raw.
- Wrapped AES keys, AES-GCM nonces, and ciphertexts are stored in the package record.

## Crypto Experiment Modes

Default mode:

```text
secure
```

Set a mode with PowerShell before starting the app:

```powershell
$env:SECUREDROP_CRYPTO_MISTAKE_MODE="nonce-reuse"
mvn spring-boot:run
```

Clear the mode and return to secure default:

```powershell
Remove-Item Env:SECUREDROP_CRYPTO_MISTAKE_MODE
```

Available modes:

| Mode | What It Demonstrates | Security Impact |
| --- | --- | --- |
| `secure` | Correct hybrid encryption | Baseline secure behavior |
| `nonce-reuse` | Reuses the AES-GCM nonce | Breaks GCM safety assumptions |
| `weak-rng` | Uses predictable random values | Keys/nonces can become guessable |
| `skip-tag-verification` | Decrypts while ignoring failed GCM tag checks | Breaks message integrity/authentication |
| `insecure-rsa-padding` | Uses RSA PKCS#1 v1.5 padding instead of OAEP | Demonstrates insecure RSA padding choice |
| `aes-key-reuse` | Reuses one AES key across packages | Breaks session/key separation |

Responses from send/read include `cryptoMode` so the active mode is visible during demos.

## Workbench Evidence Queries

Inspect stored users:

```sql
SELECT id, username, email, created_at
FROM app_users;
```

Confirm private keys are encrypted, not raw PEM:

```sql
SELECT username, LEFT(encrypted_private_key_pem, 80) AS encrypted_private_key_preview
FROM app_users;
```

Inspect stored packages:

```sql
SELECT id, sender_id, recipient_id, message_nonce, LEFT(encrypted_message, 80) AS ciphertext_preview
FROM secure_packages
ORDER BY id DESC;
```

Nonce reuse demo:

```sql
SELECT id, message_nonce
FROM secure_packages
ORDER BY id DESC
LIMIT 2;
```

In `nonce-reuse` mode, the two most recent nonces should match.

## Tests

Run:

```powershell
mvn test
```

Current expected result:

```text
Tests run: 11, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Test coverage includes:

- User registration and encrypted private-key storage
- Send/read hybrid encryption flow
- AES-GCM tamper rejection in secure mode
- JWT token validation and tamper rejection
- All five crypto mistake modes

## Notes For Demo

Recommended presentation order:

1. Run in default `secure` mode.
2. Register Alice and Bob.
3. Login and show JWT token issuance.
4. Send a message from Alice to Bob.
5. Show ciphertext/nonces in MySQL Workbench.
6. Read/decrypt as Bob.
7. Switch to one crypto mistake mode.
8. Repeat the relevant test/demo and explain the security impact.

## Git Hygiene

`target/` is ignored and should not be committed.

Commit README changes:

```powershell
git add README.md
git commit -m "Add project README"
git push origin main
```
