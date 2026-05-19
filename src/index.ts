import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Buffer } from 'buffer';
import { getJsonRpcFullnodeUrl as getFullnodeUrl, SuiJsonRpcClient as SuiClient } from '@mysten/sui/jsonRpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;
const NETWORK = (process.env.SUI_NETWORK as 'testnet' | 'mainnet' | 'devnet') || 'testnet';
const client = new SuiClient({ url: getFullnodeUrl(NETWORK), network: NETWORK });

// Initialize Admin Keypair
const secretKeyStr = process.env.ADMIN_SECRET_KEY || '';
const adminKeypair = secretKeyStr.startsWith('suiprivkey1')
  ? Ed25519Keypair.fromSecretKey(secretKeyStr)
  : Ed25519Keypair.fromSecretKey(Buffer.from(secretKeyStr, 'base64'));

const PACKAGE_ID = process.env.PACKAGE_ID;

app.get('/health', (req, res) => {
  res.json({ status: 'ok', network: NETWORK, admin: adminKeypair.getPublicKey().toSuiAddress() });
});

/**
 * Endpoint to securely upload file to Walrus and auto-transfer ownership to the user/admin
 */
app.post('/upload', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  try {
    const { targetAddress, isCustom } = req.query;

    if (!targetAddress || typeof targetAddress !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid targetAddress parameter' });
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
    const walrusUrl = `${publisherUrl}/v1/blobs?epochs=${epochs}&send_object_to=${targetAddress}`;

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

    if (!txBytes || !userAddress) {
      return res.status(400).json({ error: 'Missing txBytes or userAddress' });
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

    // 3. SET GAS SPONSOR
    // Admin pays for gas (which includes the Walrus storage fee if it's part of the PTB)
    tx.setGasOwner(adminKeypair.getPublicKey().toSuiAddress());
    
    // 4. SIGN AS SPONSOR
    const { signature } = await tx.sign({
        client,
        signer: adminKeypair,
    });

    // 5. RETURN SPONSORED DATA
    res.json({
      signature,
      // The frontend will now combine this with its own signature and execute
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
