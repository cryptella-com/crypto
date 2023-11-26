import { describe, test, expect, beforeAll, beforeEach } from '@jest/globals';
import { SIGNATURE_TYPE, signRequest, verifyRequest } from '../lib/request-signing';
import { generateKeyPair } from '../lib/ecdsa';

describe('Sign request', () => {
  const method = 'POST';
  const url = 'http://localhost/test';
  const headers = {
    'content-type': 'text/plain',
    'x-header-1': '123',
  };
  const headersArr = Object.entries(headers);
  const body = 'Hello World';

  let kp: CryptoKeyPair;

  beforeAll(async () => {
    kp = await generateKeyPair();
  });

  test('should sign request', async () => {
    const { authorization } = await signRequest(
      kp,
      method,
      url,
      headersArr,
      body,
    );
    expect(authorization).toContain(SIGNATURE_TYPE);
  });

  test('should verify request signature', async () => {
    const { authorization } = await signRequest(
      kp,
      method,
      url,
      headersArr,
      body,
    );
    expect(authorization).toContain(SIGNATURE_TYPE);
    const { ok, publicKey } = await verifyRequest(
      method,
      url,
      headers,
      body,
      {
        authorization,
      }
    );
    expect(ok).toEqual(true);
    expect(publicKey).toBeDefined();
  });

  test('verification should fail if url does not match', async () => {
    const { authorization } = await signRequest(
      kp,
      method,
      url,
      headersArr,
      body,
    );
    const { ok } = await verifyRequest(
      method,
      'http://other-domain.com/test',
      headers,
      body,
      {
        authorization,
      },
    );
    expect(ok).toEqual(false);
  });

  test('verification should fail if request header is missing', async () => {
    const { authorization } = await signRequest(
      kp,
      method,
      url,
      headersArr,
      body,
    );
    const { ok } = await verifyRequest(
      method,
      url,
      {},
      body,
      {
        authorization,
      },
    );
    expect(ok).toEqual(false);
  });
});