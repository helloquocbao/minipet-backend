# MiniPet Backend Service ⚡
Node.js Express backend server acting as the gatekeeper for transaction sponsorship (gas & Walrus storage fee payments) and secure asset uploads to the Walrus Protocol.

---

## 🔒 Security Gatekeeping Architecture

To prevent abuse and avoid draining the admin's gas wallet, the backend does not offer open, public sponsorships. Instead, it enforces strict on-chain validation:

### 1. `/upload` (POST)
- Uploads custom pet assets (avatar, spritesheet) to Walrus Protocol.
- **Security Check**:
  - If `isCustom = true`, queries the Sui RPC to verify if the requesting `targetAddress` owns an active `MintSlot` object. If not, the upload is rejected with a `403 Forbidden`.
  - If `isCustom = false` (Admin upload), verifies that the requesting `targetAddress` is exactly the admin's address.

### 2. `/sponsor` (POST)
- Signs gas payment signatures for user-constructed Move transactions.
- **Security Check**:
  - Queries Sui RPC to ensure the user wallet (`userAddress`) holds a `MintSlot` on-chain. If verified, the server signs as the transaction gas sponsor using the private key `ADMIN_SECRET_KEY` and returns the signature.

---

## ⚙️ Configuration & Environment Setup

Create a `.env` file in the root of `minipet-backend`:
```ini
PORT=3001
SUI_NETWORK=testnet
ADMIN_SECRET_KEY=suiprivkey1................ # Exported from 'sui keytool export'

PACKAGE_ID=0xfc0ec477...                    # Your deployed Sui package ID
GLOBAL_CONFIG_ID=0xffc5bb...                # Deployed global config object ID
WALRUS_PUBLISHER_URL=https://publisher.walrus-testnet.walrus.space
```

---

## 📦 Running locally

```bash
# Install dependencies
npm install

# Start in development watch mode using tsx
npm run dev

# Compile TypeScript to JavaScript
npm run build

# Start production server
npm run start
```
