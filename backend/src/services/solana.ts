import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import {
  getOrCreateAssociatedTokenAccount,
  createTransferInstruction,
  getMint,
  getAccount,
} from '@solana/spl-token';
import bs58 from 'bs58';
import crypto from 'crypto';

const ENCRYPTION_KEY = process.env.JWT_SECRET || 'change-me-in-production';

// Connect to Solana
export function getConnection(): Connection {
  const rpcUrl = process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com';
  return new Connection(rpcUrl, 'confirmed');
}

// Get USDC mint address
export function getUsdcMint(): PublicKey {
  return new PublicKey(
    process.env.USDC_MINT_ADDRESS || '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
  );
}

// Generate a new Solana keypair
export function generateKeypair(): Keypair {
  return Keypair.generate();
}

// Encrypt a private key for storage
export function encryptPrivateKey(secretKey: Uint8Array): string {
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(ENCRYPTION_KEY, 'agentpay-salt', 32);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(secretKey)), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Decrypt a private key from storage
export function decryptPrivateKey(encrypted: string): Uint8Array {
  const [ivHex, dataHex] = encrypted.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');
  const key = crypto.scryptSync(ENCRYPTION_KEY, 'agentpay-salt', 32);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return new Uint8Array(decrypted);
}

// Get USDC balance for a wallet
export async function getUsdcBalance(walletPublicKey: string): Promise<number> {
  const connection = getConnection();
  const mint = getUsdcMint();
  const owner = new PublicKey(walletPublicKey);

  try {
    const tokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      Keypair.generate(), // payer doesn't matter for reading
      mint,
      owner
    );
    const mintInfo = await getMint(connection, mint);
    const balance = Number(tokenAccount.amount) / Math.pow(10, mintInfo.decimals);
    return balance;
  } catch {
    return 0;
  }
}

// Transfer USDC between wallets
export async function transferUsdc(
  fromEncryptedKey: string,
  toPublicKey: string,
  amount: number
): Promise<string> {
  const connection = getConnection();
  const mint = getUsdcMint();

  // Decrypt sender's private key
  const fromSecretKey = decryptPrivateKey(fromEncryptedKey);
  const fromKeypair = Keypair.fromSecretKey(fromSecretKey);
  const toOwner = new PublicKey(toPublicKey);

  // Get or create token accounts
  const fromTokenAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    fromKeypair,
    mint,
    fromKeypair.publicKey
  );

  const toTokenAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    fromKeypair, // sender pays for account creation if needed
    mint,
    toOwner
  );

  // Get decimals
  const mintInfo = await getMint(connection, mint);
  const transferAmount = BigInt(Math.round(amount * Math.pow(10, mintInfo.decimals)));

  // Build and send transaction
  const instruction = createTransferInstruction(
    fromTokenAccount.address,
    toTokenAccount.address,
    fromKeypair.publicKey,
    transferAmount
  );

  const transaction = new Transaction().add(instruction);
  transaction.feePayer = fromKeypair.publicKey;
  const latestBlockhash = await connection.getLatestBlockhash();
  transaction.recentBlockhash = latestBlockhash.blockhash;

  transaction.sign(fromKeypair);
  const signature = await connection.sendRawTransaction(transaction.serialize());
  await connection.confirmTransaction({
    signature,
    blockhash: latestBlockhash.blockhash,
    lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
  });

  return signature;
}

// Request devnet SOL airdrop (for testing - pays tx fees)
export async function requestAirdrop(publicKey: string, solAmount: number = 1): Promise<string> {
  const connection = getConnection();
  const key = new PublicKey(publicKey);
  const signature = await connection.requestAirdrop(key, solAmount * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(signature);
  return signature;
}

// Get SOL balance (needed for tx fees)
export async function getSolBalance(publicKey: string): Promise<number> {
  const connection = getConnection();
  const balance = await connection.getBalance(new PublicKey(publicKey));
  return balance / LAMPORTS_PER_SOL;
}
