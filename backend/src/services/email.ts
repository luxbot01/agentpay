import { Resend } from 'resend';

const resend = new Resend(process.env.RESEND_API_KEY);

const FROM_ADDRESS = 'AgentPay <onboarding@resend.dev>';

export async function sendVerificationEmail(to: string, code: string): Promise<void> {
  const result = await resend.emails.send({
    from: FROM_ADDRESS,
    to,
    subject: 'Verify your AgentPay account',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h1 style="color: #1DA1F2; font-size: 28px; margin-bottom: 8px;">AgentPay</h1>
        <p style="color: #657786; margin-bottom: 24px;">Venmo for AI Agents</p>
        <p style="color: #14171A; font-size: 16px;">Your verification code is:</p>
        <div style="background: #E8F5FE; border-radius: 12px; padding: 24px; text-align: center; margin: 16px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1DA1F2;">${code}</span>
        </div>
        <p style="color: #657786; font-size: 14px;">This code expires in 15 minutes. If you didn't create an AgentPay account, you can safely ignore this email.</p>
      </div>
    `,
  });
  console.log('Verification email result:', JSON.stringify(result));
}

export async function sendPasswordResetEmail(to: string, code: string): Promise<void> {
  const result = await resend.emails.send({
    from: FROM_ADDRESS,
    to,
    subject: 'Reset your AgentPay password',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h1 style="color: #1DA1F2; font-size: 28px; margin-bottom: 8px;">AgentPay</h1>
        <p style="color: #657786; margin-bottom: 24px;">Password Reset</p>
        <p style="color: #14171A; font-size: 16px;">Your password reset code is:</p>
        <div style="background: #E8F5FE; border-radius: 12px; padding: 24px; text-align: center; margin: 16px 0;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #1DA1F2;">${code}</span>
        </div>
        <p style="color: #657786; font-size: 14px;">This code expires in 15 minutes. If you didn't request a password reset, you can safely ignore this email.</p>
      </div>
    `,
  });
  console.log('Password reset email result:', JSON.stringify(result));
}

export function generateCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
