# 🔐 Keycloak WebAuthn & Custom Authentication

Welcome to the **Keycloak WebAuthn & Custom Authentication** repository! 🚀

This project demonstrates how to integrate **WebAuthn (Passkeys) with Keycloak** and implement **custom token-based authentication** using Keycloak's APIs. Our setup includes:
- **WebAuthn (Passkeys)** for passwordless authentication
- **Custom token generation** (Access & Refresh Tokens)
- **Integration with Keycloak** for user management

## 📌 Features

✅ Secure authentication using **WebAuthn (Passkeys)** 🔑  
✅ Custom endpoints for **registering & authenticating passkeys** 🖊️  
✅ Custom **JWT access tokens** with Keycloak's signing key 🛡️  
✅ Integration with **Keycloak’s credential store** 🏦  
✅ Fully working **frontend UI** for passkey creation 🎨  
✅ Backend written in **Java with JAX-RS** for Keycloak extensions  
✅ Uses **RSA private/public key signing** for JWT verification ✍️  

---

## 🚀 Getting Started

### **1️⃣ Clone the Repository**
```sh
  git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME.git
  cd YOUR_REPO_NAME
```

### **2️⃣ Run Keycloak (Docker Recommended)**
Ensure you have Keycloak running locally.
```sh
  docker run -d --name keycloak -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev
```

### **3️⃣ Setup Keycloak Realm & Users**
1. Open [http://localhost:8080](http://localhost:8080)
2. Login with **admin/admin** (default)
3. Create a new **Realm**
4. Add a **User** and enable **WebAuthn Credentials**

### **4️⃣ Backend Setup (Java API)**
1. Install dependencies
```sh
  mvn clean install
```
2. Run the backend
```sh
  mvn quarkus:dev
```

### **5️⃣ Frontend Setup (React + WebAuthn API)**
```sh
  cd frontend
  npm install
  npm run dev
```

---

## 🔑 WebAuthn Registration & Authentication Flow

### **1️⃣ Fetch a Challenge from Backend**
```ts
const response = await fetch("http://localhost:8000/api/passkey/challenge");
const { challenge } = await response.json();
```

### **2️⃣ Create Passkey with WebAuthn API**
```ts
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: Uint8Array.from(atob(challenge), (c) => c.charCodeAt(0)),
    rp: { name: "My App", id: window.location.hostname },
    user: { id: new Uint8Array(16), name: "user@example.com", displayName: "User Name" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { userVerification: "preferred", residentKey: "required" },
    attestation: "none",
  },
});
```

### **3️⃣ Send Passkey Data to Backend for Storage**
```ts
fetch("http://localhost:8000/api/passkey/save", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    username: "user@example.com",
    credentialId: credential.id,
    attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
  }),
});
```

---

## 🔑 Custom JWT Token Generation
Our backend manually generates JWT access tokens using Keycloak’s signing keys. This ensures secure authentication.

### **🔹 Custom Token Generation Code (Java)**
```java
private Response generateTokensResponse(UserModel user) {
    RealmModel realm = session.getContext().getRealm();
    KeyManager.ActiveRsaKey activeRsaKey = session.keys().getActiveRsaKey(realm);
    if (activeRsaKey == null) {
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Keycloak signing key not found").build();
    }

    AccessToken token = createAccessToken(user);
    String signedToken = encodeJWT(token, activeRsaKey);

    return Response.ok("{\"access_token\": \"" + signedToken + "\"}")
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
            .build();
}
```

### **🔹 Decode & Verify JWT using Keycloak's Public Key**
1. Open **[jwt.io](https://jwt.io)**
2. Paste the JWT token
3. Fetch Keycloak's **public key** from `http://localhost:8080/realms/YOUR_REALM`
4. Verify the signature!

---

## 🔧 API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/passkey/challenge` | `GET` | Generate WebAuthn challenge |
| `/api/passkey/save` | `POST` | Save registered passkey |
| `/api/auth/token` | `POST` | Generate custom access token |

---

## 🛠️ Tech Stack
- **Backend:** Java (JAX-RS, Keycloak SPI)
- **Frontend:** React + WebAuthn API
- **Authentication:** WebAuthn, JWT, Keycloak
- **Database:** Keycloak’s internal store
- **Deployment:** Docker

---

## 🏗️ Future Improvements
🚀 Add WebAuthn **login endpoint**  
🚀 Implement **FIDO2 biometric authentication**  
🚀 Enhance **error handling & logging**  

---

## 🤝 Contributing
Feel free to open **issues** or submit **pull requests** if you have improvements or suggestions! 🎉

---

## ⭐ Acknowledgments
Special thanks to **Keycloak** for providing an open-source identity and access management solution!

📌 *Star this repo if you found it helpful!* 🌟

