import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Buffer } from 'buffer';
import { getJsonRpcFullnodeUrl as getFullnodeUrl, SuiJsonRpcClient as SuiClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { jwtToAddress } from '@mysten/sui/zklogin';

dotenv.config();

// 1. STARTUP VALIDATION CHECKS
if (!process.env.ADMIN_SECRET_KEY) {
  console.error("❌ ADMIN_SECRET_KEY is missing from environment variables!");
  process.exit(1);
}
if (!process.env.PACKAGE_ID) {
  console.error("❌ PACKAGE_ID is missing from environment variables!");
  process.exit(1);
}
if (!process.env.ZKLOGIN_SALT) {
  console.error("❌ ZKLOGIN_SALT is missing from environment variables!");
  process.exit(1);
}
if (!process.env.GOOGLE_CLIENT_ID) {
  console.error("❌ GOOGLE_CLIENT_ID is missing from environment variables!");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const NETWORK = (process.env.SUI_NETWORK as 'testnet' | 'mainnet' | 'devnet') || 'testnet';
const client = new SuiClient({ url: getFullnodeUrl(NETWORK), network: NETWORK });

// Initialize Admin Keypair
const secretKeyStr = process.env.ADMIN_SECRET_KEY;
const adminKeypair = secretKeyStr.startsWith('suiprivkey1')
  ? Ed25519Keypair.fromSecretKey(secretKeyStr)
  : Ed25519Keypair.fromSecretKey(Buffer.from(secretKeyStr, 'base64'));

const PACKAGE_ID = process.env.PACKAGE_ID;
const SUI_ADDRESS_REGEX = /^0x[a-fA-F0-9]{1,64}$/;

function normalizeSuiAddress(addr: string): string {
  let clean = addr.toLowerCase().trim();
  if (clean.startsWith('0x')) {
    clean = clean.substring(2);
  }
  return '0x' + clean.padStart(64, '0');
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', network: NETWORK, admin: adminKeypair.getPublicKey().toSuiAddress() });
});

/**
 * Endpoint to securely derive a zkLogin address using backend-only Salt (SEC-04)
 */
app.post('/derive-address', async (req, res) => {
  try {
    const { jwt } = req.body;
    if (!jwt || typeof jwt !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid jwt payload' });
    }

    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return res.status(400).json({ error: 'Invalid JWT structure' });
    }

    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
    
    // Validate JWT claims
    if (payload.aud !== process.env.GOOGLE_CLIENT_ID) {
      return res.status(400).json({ error: 'Invalid JWT audience' });
    }
    if (payload.iss !== 'https://accounts.google.com' && payload.iss !== 'accounts.google.com') {
      return res.status(400).json({ error: 'Invalid JWT issuer' });
    }
    if (payload.exp < Date.now() / 1000) {
      return res.status(400).json({ error: 'JWT has expired' });
    }

    const address = jwtToAddress(jwt, BigInt(process.env.ZKLOGIN_SALT!), false);
    res.json({ address });
  } catch (error: any) {
    console.error('Derive address error:', error);
    res.status(500).json({ error: error.message || 'Failed to derive address' });
  }
});

/**
 * Endpoint to securely upload file to Walrus and auto-transfer ownership to the user/admin (SEC-05)
 */
app.post('/upload', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  try {
    const { targetAddress, isCustom } = req.query;

    if (!targetAddress || typeof targetAddress !== 'string' || !SUI_ADDRESS_REGEX.test(targetAddress)) {
      return res.status(400).json({ error: 'Missing or invalid targetAddress parameter (must be 0x...)' });
    }

    // Verify raw request body presence and length
    if (!req.body || req.body.length === 0) {
      return res.status(400).json({ error: 'Empty payload provided for upload' });
    }

    const isCustomBool = isCustom === 'true';

    // 1. SECURITY CHECKS (SEC-05: Authenticate targetAddress ownership)
    const authHeader = req.headers['authorization'];
    const signatureHeader = req.headers['x-sui-signature'];
    let isAuthorized = false;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      // zkLogin verification via JWT
      const jwt = authHeader.substring(7);
      try {
        const parts = jwt.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
        if (
          payload.aud === process.env.GOOGLE_CLIENT_ID &&
          (payload.iss === 'https://accounts.google.com' || payload.iss === 'accounts.google.com') &&
          payload.exp > Date.now() / 1000
        ) {
          const derivedAddress = jwtToAddress(jwt, BigInt(process.env.ZKLOGIN_SALT!), false);

          if (normalizeSuiAddress(derivedAddress) === normalizeSuiAddress(targetAddress)) {
            isAuthorized = true;
          }
        }
      } catch (jwtErr) {
        console.error('[Upload Auth] JWT check failed:', jwtErr);
      }
    } else if (signatureHeader && typeof signatureHeader === 'string') {
      // Standard signature verification for Extension Wallet
      try {
        const message = `MiniPet Upload: ${targetAddress}`;
        const messageBytes = new TextEncoder().encode(message);
        const { verifyPersonalMessageSignature } = await import('@mysten/sui/verify');
        
        // Verify the signature is valid for the message and extract public key
        const publicKey = await verifyPersonalMessageSignature(messageBytes, signatureHeader, {
          client: client
        });
        const derivedAddress = publicKey.toSuiAddress();
        
        console.log(`[Upload Auth] verify signature: derivedAddress=${derivedAddress}, targetAddress=${targetAddress}`);
        
        if (normalizeSuiAddress(derivedAddress) === normalizeSuiAddress(targetAddress)) {
          isAuthorized = true;
        } else {
          console.warn(`[Upload Auth] Mismatch: derived ${normalizeSuiAddress(derivedAddress)} vs target ${normalizeSuiAddress(targetAddress)}`);
        }
      } catch (sigErr) {
        console.error('[Upload Auth] Signature check failed:', sigErr);
      }
    }

    if (!isAuthorized) {
      return res.status(401).json({ error: 'Unauthorized: Invalid credentials or signature for targetAddress' });
    }

    if (isCustomBool) {
      // Custom Pet Flow: Verify user owns a MintSlot on-chain
      const objects = await client.getOwnedObjects({
        owner: targetAddress,
        filter: { StructType: `${PACKAGE_ID}::pet_nft::MintSlot` }
      });

      if (objects.data.length === 0) {
        return res.status(403).json({ error: 'User does not own a MintSlot. Upload denied.' });
      }
      console.log(`[Upload] User ${targetAddress} verified with active MintSlot.`);
    } else {
      // Admin Flow: Verify targetAddress is the Admin address
      const adminAddress = adminKeypair.getPublicKey().toSuiAddress();
      if (targetAddress.toLowerCase() !== adminAddress.toLowerCase()) {
        return res.status(403).json({ error: 'Only admin can perform admin uploads.' });
      }
      console.log(`[Upload] Admin ${targetAddress} verified.`);
    }

    // 2. UPLOAD TO WALRUS & TRANSFER OWNERSHIP ON-CHAIN (using send_object_to)
    const epochs = 40;
    const publisherUrl = process.env.WALRUS_PUBLISHER_URL || process.env.VITE_WALRUS_PUBLISHER_URL || 'https://publisher.walrus-testnet.walrus.space';
    const walrusUrl = `${publisherUrl}/v1/blobs?epochs=${epochs}&send_object_to=${encodeURIComponent(targetAddress)}`;

    console.log(`[Upload] Requesting Walrus storage & transfer to ${targetAddress}...`);

    const response = await fetch(walrusUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': req.headers['content-type'] || 'application/octet-stream',
      },
      body: req.body,
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(500).json({ error: `Walrus upload failed: ${errorText}` });
    }

    const data = await response.json();
    console.log(`[Upload] Successfully uploaded and transferred to ${targetAddress}. Response:`, JSON.stringify(data));
    res.json(data);
  } catch (error) {
    console.error('Upload handling error:', error);
    res.status(500).json({ error: 'Internal server error during upload' });
  }
});

/**
 * Endpoint to sponsor a transaction (Gas & Walrus fees) (SEC-02)
 */
app.post('/sponsor', async (req, res) => {
  try {
    console.log('[Backend Sponsor] Received req.body:', JSON.stringify(req.body));
    const { txBytes, userAddress, userSignature } = req.body;

    if (!txBytes || !userAddress || typeof userAddress !== 'string' || !SUI_ADDRESS_REGEX.test(userAddress)) {
      console.warn('[Backend Sponsor] Validation failed. txBytes length:', txBytes ? txBytes.length : 0, 'userAddress:', userAddress);
      return res.status(400).json({ error: 'Missing or invalid txBytes or userAddress' });
    }

    // 1. RECONSTRUCT TRANSACTION & SECURITY CHECK: Validate Sender (SEC-02)
    const tx = Transaction.from(txBytes);
    const txSender = tx.getData().sender;
    if (!txSender || normalizeSuiAddress(txSender) !== normalizeSuiAddress(userAddress)) {
      console.warn(`[Sponsor Abuse Blocked] Mismatched sender: txSender ${txSender} vs userAddress ${userAddress}`);
      return res.status(403).json({ error: 'Sponsorship denied: Transaction sender must match userAddress.' });
    }

    // 2. TRANSACTION INSPECTION & SPONSORSHIP POLICIES
    let bypassMintSlotCheck = false;
    const normalizedPackageId = normalizeSuiAddress(PACKAGE_ID);
    for (const command of tx.getData().commands) {
      if (command.$kind === 'MoveCall') {
        const cmdPackage = command.MoveCall.package;
        const cmdModule = command.MoveCall.module;
        const cmdFunction = command.MoveCall.function;

        if (normalizeSuiAddress(cmdPackage) !== normalizedPackageId) {
          console.warn(`[Sponsor Abuse Blocked] User ${userAddress} attempted to sponsor call to unauthorized package: ${cmdPackage}`);
          return res.status(403).json({ error: 'Sponsorship denied: Transaction calls unauthorized packages.' });
        }

        if (cmdModule === 'pet_nft' && (cmdFunction === 'buy_mint_slot' || cmdFunction === 'buy_pet')) {
          bypassMintSlotCheck = true;
        }
      }
    }

    // A. Limit Gas budget (Max 100,000,000 MIST = 0.1 SUI) to prevent draining
    const gasBudget = tx.getData().gasData.budget;
    if (gasBudget && Number(gasBudget) > 100_000_000) {
      return res.status(403).json({ error: 'Sponsorship denied: Transaction gas budget is too high (max 0.1 SUI).' });
    }

    // 3. SECURITY CHECK: Verify user has a Mint Slot on-chain (Unless they are buying a slot or pet)
    if (!bypassMintSlotCheck) {
      const objects = await client.getOwnedObjects({
        owner: userAddress,
        filter: { StructType: `${PACKAGE_ID}::pet_nft::MintSlot` }
      });

      if (objects.data.length === 0) {
        return res.status(403).json({ error: 'User does not own a MintSlot. Sponsorship denied.' });
      }
    }

    // 4. SIGN AS SPONSOR
    const rawTxBytes = Buffer.from(txBytes, 'base64');
    const { signature: sponsorSignature } = await adminKeypair.signTransaction(rawTxBytes);

    // 5. COMBINE SIGNATURES & EXECUTE ON-CHAIN (If userSignature is provided)
    if (userSignature) {
      console.log(`[Sponsor] Executing sponsored transaction for ${userAddress} directly...`);
      const result = await client.executeTransactionBlock({
        transactionBlock: rawTxBytes,
        signature: [userSignature, sponsorSignature],
        options: { showEffects: true, showEvents: true }
      });
      console.log(`Successfully executed sponsored transaction for ${userAddress}. Digest: ${result.digest}`);
      return res.json({
        success: true,
        digest: result.digest,
      });
    }

    // Fallback: If userSignature is not provided yet, just return the sponsor signature
    res.json({
      signature: sponsorSignature,
    });
  } catch (error: any) {
    console.error('Sponsorship execution error:', error);
    res.status(500).json({ error: error.message || 'Internal server error during sponsorship' });
  }
});

/**
 * Endpoint to request a sponsor SUI gas coin for transaction building (SEC-02)
 */
app.get('/sponsor-gas-coin', async (req, res) => {
  try {
    const adminAddress = adminKeypair.getPublicKey().toSuiAddress();
    console.log(`[Sponsor Gas] Fetching SUI gas coins for admin ${adminAddress}...`);

    const coins = await client.getCoins({
      owner: adminAddress,
      coinType: '0x2::sui::SUI'
    });

    // Find a SUI coin with sufficient balance for gas budget (e.g., at least 0.1 SUI = 100,000,000 MIST)
    const gasCoin = coins.data.find(c => BigInt(c.balance) >= 50_000_000n);

    if (!gasCoin) {
      console.error('[Sponsor Gas] Admin does not have any SUI coins with balance >= 0.05 SUI');
      return res.status(500).json({ error: 'Admin has no suitable SUI gas coins left.' });
    }

    res.json({
      sponsorAddress: adminAddress,
      gasCoin: {
        objectId: gasCoin.coinObjectId,
        version: gasCoin.version,
        digest: gasCoin.digest
      }
    });
  } catch (error: any) {
    console.error('[Sponsor Gas] Error fetching sponsor SUI gas coin:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch sponsor gas coin' });
  }
});

/**
 * Faucet endpoint for users to claim MIPET utility token on testnet
 */
app.post('/faucet', async (req, res) => {
  try {
    const { recipient } = req.body;
    if (!recipient || typeof recipient !== 'string' || !SUI_ADDRESS_REGEX.test(recipient)) {
      return res.status(400).json({ error: 'Missing or invalid recipient address' });
    }

    const FAUCET_AMOUNT = 10000_000000000n; // 10,000 MIPET
    const PET_TOKEN_TYPE = `${process.env.PET_TOKEN_PACKAGE_ID || '0x46af6cc67f8a40f6a4a5267087176e6e4341e51df6e9decabfe07cf606186e23'}::pet_token::PET_TOKEN`;

    console.log(`[Faucet] Transferring MIPET tokens to ${recipient}...`);

    const tx = new Transaction();
    tx.setSender(adminKeypair.getPublicKey().toSuiAddress());

    // Get admin's MIPET coins
    const coins = await client.getCoins({ owner: adminKeypair.getPublicKey().toSuiAddress(), coinType: PET_TOKEN_TYPE });
    if (!coins.data.length) {
      return res.status(500).json({ error: 'Admin wallet has no MIPET tokens' });
    }

    const [coin] = tx.splitCoins(tx.object(coins.data[0].coinObjectId), [FAUCET_AMOUNT]);
    tx.transferObjects([coin], recipient);

    const result = await client.signAndExecuteTransaction({
      signer: adminKeypair,
      transaction: tx,
    });

    await client.waitForTransaction({ digest: result.digest });

    console.log(`[Faucet] Successfully transferred to ${recipient}. Tx: ${result.digest}`);
    res.json({ success: true, digest: result.digest });
  } catch (error: any) {
    console.error('[Faucet] Error:', error);
    res.status(500).json({ error: error.message || 'Faucet request failed' });
  }
});

app.listen(PORT, () => {
  console.log(`MiniPet Backend running on http://localhost:${PORT}`);
});
