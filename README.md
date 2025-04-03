# 🔐 Keycloak WebAuthn & Custom Authentication

Welcome to the **Keycloak WebAuthn & Custom Authentication** repository! 🚀

This project demonstrates how to integrate **WebAuthn (Passkeys) with Keycloak** and implement **custom token-based authentication** using Keycloak's APIs. Our setup includes:
- **WebAuthn (Passkeys)** for passwordless authentication
- **Custom token generation** (Access & Refresh Tokens)
- **Integration with Keycloak** for user management

## 📌 Features

✅ Secure authentication using **WebAuthn (Passkeys)** 🔑  
✅ Custom endpoints for **registering & authenticating passkeys** 🖊️   
✅ Integration with **Keycloak’s credential store** 🏦  
✅ Backend written in **Java with JAX-RS** for Keycloak extensions✍️  

---

## 🚀 Getting Started

### **1️⃣ Clone the Repository**
```sh
  git clone https://github.com/sagargupta2001/keycloak-custom-passkey
  cd keycloak-custom-passkey
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
### 1. Build the Custom Provider JAR

Compile the Java project into a JAR file:

```sh
mvn clean package
```

This will generate a JAR file inside the `target/` directory.

### 2. Copy the JAR to Keycloak’s `providers` Directory

Move the JAR file to Keycloak’s `providers/` directory:

```sh
cp target/custom-webauthn-provider.jar /path/to/keycloak/providers/
```

### 3. Restart Keycloak

Apply the changes by restarting Keycloak:

```sh
/path/to/keycloak/bin/kc.sh start-dev
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

## 🔧 API Endpoints
| Endpoint | Method | Description                  |
|----------|--------|------------------------------|
| `/api/passkey/challenge` | `GET`  | Generate WebAuthn challenge  |
| `/api/passkey/save` | `POST` | Save registered passkey      |
| `/api/passkey/get-credential-id` | `GET`  | Get credId & challenge       |
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
🚀 Unit Testing 
🚀 Enhance **error handling & logging**  

---

## 🤝 Contributing
Feel free to open **issues** or submit **pull requests** if you have improvements or suggestions! 🎉

---

## ⭐ Acknowledgments
Special thanks to **Keycloak** for providing an open-source identity and access management solution!

📌 *Star this repo if you found it helpful!* 🌟

