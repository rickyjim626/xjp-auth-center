import { randomBytes, createHash } from 'crypto';

export function generateRandomId(length = 32): string {
  return randomBytes(length).toString('base64url');
}

export function generateLoginId(): string {
  return `login_${generateRandomId(24)}`;
}

export function generateAuthCode(): string {
  return `code_${generateRandomId(32)}`;
}

export function generateRefreshToken(): string {
  return `rt_${generateRandomId(48)}`;
}

export function sha256(data: string): string {
  return createHash('sha256').update(data).digest('base64url');
}

export function generateCodeChallenge(): string {
  return generateRandomId(43);
}

export function verifyCodeChallenge(verifier: string, challenge: string, method = 'S256'): boolean {
  if (method === 'plain') {
    return verifier === challenge;
  }
  if (method === 'S256') {
    return sha256(verifier) === challenge;
  }
  return false;
}