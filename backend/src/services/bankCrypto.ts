import crypto from 'crypto';

// Use a SEPARATE encryption key derivation from Solana keys for defense in depth.
// Even if one key is compromised, the other domain's data remains protected.
const BANK_ENCRYPTION_KEY = process.env.BANK_ENCRYPTION_KEY || process.env.JWT_SECRET || 'change-me-in-production';
const BANK_SALT = 'agentpay-bank-v1'; // Different salt from Solana key encryption

function deriveKey(): Buffer {
  return crypto.scryptSync(BANK_ENCRYPTION_KEY, BANK_SALT, 32);
}

/**
 * Encrypt a bank account or routing number using AES-256-CBC.
 * Returns "iv_hex:ciphertext_hex" format.
 * Each encryption uses a unique random IV.
 */
export function encryptBankField(plaintext: string): string {
  const iv = crypto.randomBytes(16);
  const key = deriveKey();
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

/**
 * Decrypt a bank account or routing number from AES-256-CBC.
 * Input format: "iv_hex:ciphertext_hex"
 */
export function decryptBankField(encrypted: string): string {
  const [ivHex, dataHex] = encrypted.split(':');
  if (!ivHex || !dataHex) {
    throw new Error('Invalid encrypted bank field format');
  }
  const iv = Buffer.from(ivHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');
  const key = deriveKey();
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = Buffer.concat([
    decipher.update(data),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

/**
 * Extract the last 4 characters of a string.
 */
export function getLast4(value: string): string {
  return value.slice(-4);
}
