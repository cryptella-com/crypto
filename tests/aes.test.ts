import { describe, test, expect } from 'bun:test';
import { exportPublicKey, generateKeyPair } from '../lib/ecdsa';
import {
  decrypt,
  deriveWrappingKey,
  encrypt,
  exportKey,
  generateKey,
  unwrapKey,
  wrapKey,
} from '../lib/aes';

describe('AES', () => {
  test('should derive a wrapping key from ECDSA key pair', async () => {
    const senderKP = await generateKeyPair();
    const recipientKP = await generateKeyPair();
    const recipientPubKey = await exportPublicKey(recipientKP.publicKey);
    const derivedKey = await deriveWrappingKey(senderKP, recipientPubKey);
    expect(derivedKey).toBeDefined();
  });

  test('should encrypt data', async () => {
    const text = 'Hello World';
    const key = await generateKey();
    const data = new TextEncoder().encode(text);
    const { encrypted, iv } = await encrypt(key, data);
    expect(iv.length).toBeGreaterThanOrEqual(16);
    expect(encrypted).toBeDefined();
    expect(iv).toBeDefined();
    expect(encrypted).not.toEqual(data);
  });

  test('should decrypt data', async () => {
    const key = await generateKey();
    const data = new TextEncoder().encode('Hello World');
    const { encrypted, iv } = await encrypt(key, data);
    expect(encrypted).toBeDefined();
    expect(iv).toBeDefined();
    expect(encrypted).not.toEqual(data);
    const result = await decrypt(key, encrypted, iv);
    expect(result).toEqual(data);
  });

  test('should wrap and unwrap key', async () => {
    const key = await generateKey();
    const exportedKey = await exportKey(key);
    const senderKP = await generateKeyPair();
    const recipientKP = await generateKeyPair();
    const senderPubKey = await exportPublicKey(senderKP.publicKey);
    const recipientPubKey = await exportPublicKey(recipientKP.publicKey);
    const wrappedKey = await wrapKey(key, senderKP, recipientPubKey);
    const unwrappedKey = await unwrapKey(wrappedKey, recipientKP, senderPubKey);
    expect(exportedKey).not.toEqual(wrappedKey);
    expect(exportedKey).toEqual(await exportKey(unwrappedKey));
  });
});
