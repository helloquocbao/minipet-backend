import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Buffer } from 'buffer';
import { getJsonRpcFullnodeUrl as getFullnodeUrl, SuiJsonRpcClient as SuiClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

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
 * Endpoint to securely upload file to Walrus and auto-transfer ownership to the user/admin
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

    // 1. SECURITY CHECKS
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
    const epochs = 5;
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
 * Endpoint to sponsor a transaction (Gas & Walrus fees)
 */
app.post('/sponsor', async (req, res) => {
  try {
    const { txBytes, userAddress } = req.body;

    if (!txBytes || !userAddress || typeof userAddress !== 'string' || !SUI_ADDRESS_REGEX.test(userAddress)) {
      return res.status(400).json({ error: 'Missing or invalid txBytes or userAddress' });
    }

    // 1. SECURITY CHECK: Verify user has a Mint Slot on-chain
    const objects = await client.getOwnedObjects({
      owner: userAddress,
      filter: { StructType: `${PACKAGE_ID}::pet_nft::MintSlot` }
    });

    if (objects.data.length === 0) {
      return res.status(403).json({ error: 'User does not own a MintSlot. Sponsorship denied.' });
    }

    // 2. RECONSTRUCT TRANSACTION
    const tx = Transaction.from(txBytes);

    // 3. TRANSACTION INSPECTION & SPONSORSHIP POLICIES
    // A. Limit Gas budget (Max 100,000,000 MIST = 0.1 SUI) to prevent draining
    const gasBudget = tx.getData().gasData.budget;
    if (gasBudget && Number(gasBudget) > 100_000_000) {
      return res.status(403).json({ error: 'Sponsorship denied: Transaction gas budget is too high (max 0.1 SUI).' });
    }

    // B. Verify transaction calls only target our authorized package
    const normalizedPackageId = normalizeSuiAddress(PACKAGE_ID);
    for (const command of tx.getData().commands) {
      if (command.$kind === 'MoveCall') {
        const cmdPackage = command.MoveCall.package;
        if (normalizeSuiAddress(cmdPackage) !== normalizedPackageId) {
          console.warn(`[Sponsor Abuse Blocked] User ${userAddress} attempted to sponsor call to unauthorized package: ${cmdPackage}`);
          return res.status(403).json({ error: 'Sponsorship denied: Transaction calls unauthorized packages.' });
        }
      }
    }

    // 4. SET GAS SPONSOR
    tx.setGasOwner(adminKeypair.getPublicKey().toSuiAddress());
    
    // 5. SIGN AS SPONSOR
    const { signature } = await tx.sign({
        client,
        signer: adminKeypair,
    });

    // 6. RETURN SPONSORED DATA
    res.json({
      signature,
    });

    console.log(`Successfully sponsored transaction for ${userAddress}`);
  } catch (error) {
    console.error('Sponsorship error:', error);
    res.status(500).json({ error: 'Internal server error during sponsorship' });
  }
});

app.listen(PORT, () => {
  console.log(`MiniPet Backend running on http://localhost:${PORT}`);
});
