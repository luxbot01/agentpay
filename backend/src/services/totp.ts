import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { encryptTotpSecret, decryptTotpSecret } from './totpCrypto';

export interface TotpSetup {
  secret: string;
  qrCodeDataUrl: string;
}

export async function generateTotpSecret(userEmail: string): Promise<TotpSetup> {
  const secret = speakeasy.generateSecret({
    name: `AgentPay (${userEmail})`,
    issuer: 'AgentPay',
    length: 32,
  });

  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

  return {
    secret: secret.base32,
    qrCodeDataUrl,
  };
}

export function verifyTotpToken(encryptedSecret: string, token: string): boolean {
  const secret = decryptTotpSecret(encryptedSecret);
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2,
  });
}

export function encryptSecret(plainSecret: string): string {
  return encryptTotpSecret(plainSecret);
}
