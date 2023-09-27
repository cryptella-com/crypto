import { describe, test, expect, beforeAll } from 'bun:test';
import {
  PUB_KEY_LEN,
  TCurveName,
  exportPrivateKey,
  exportPublicKey,
  generateKeyPair,
  getCurveFromPublicKey,
  importKeyPair,
  importPublicKey,
  isValidPublicKey,
  sign,
  verify,
} from '../lib/ecdsa';

describe('ECDSA', () => {
  const curves: TCurveName[] = ['P-256', 'P-384', 'P-521'];

  for (let curve of curves) {
    const expectedPubKeySize = PUB_KEY_LEN[curve];
    const expectedPubKeyCompressedSize = (PUB_KEY_LEN[curve] - 1) / 2 + 1;
    const expectedMinPrivKeySize = expectedPubKeyCompressedSize - 2;
    const expectedMinSigSize = expectedMinPrivKeySize * 2;

    describe(curve, () => {
      describe('generateKey()', () => {
        test('should generate a key-pair and return them as CryptoKey', async () => {
          const kp = await generateKeyPair(curve);
          expect(kp).toBeTruthy();
          expect(kp.privateKey).toBeInstanceOf(CryptoKey);
          expect(kp.publicKey).toBeInstanceOf(CryptoKey);
        });
      });

      describe('Export', () => {
        let kp: CryptoKeyPair;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
        });

        describe('exportPublicKey()', () => {
          test(`should export public key as Uint8Array with ${expectedPubKeySize} bytes`, async () => {
            const pubKey = await exportPublicKey(kp.publicKey);
            expect(pubKey).toBeInstanceOf(Uint8Array);
            expect(pubKey.length).toBe(expectedPubKeySize);
          });

          test(`should export compressed public key as Uint8Array with ${expectedPubKeyCompressedSize} bytes`, async () => {
            const pubKey = await exportPublicKey(kp.publicKey, true);
            expect(pubKey).toBeInstanceOf(Uint8Array);
            expect(pubKey.length).toBe(expectedPubKeyCompressedSize);
          });
        });

        describe('exportPrivateKey()', () => {
          test(`should export private key as Uint8Array with min ${expectedMinPrivKeySize} bytes`, async () => {
            const privKey = await exportPrivateKey(kp.privateKey);
            expect(privKey).toBeInstanceOf(Uint8Array);
            expect(privKey.length).toBeGreaterThanOrEqual(
              expectedMinPrivKeySize
            );
          });
        });
      });

      describe('Import', () => {
        let kp: CryptoKeyPair;
        let pubKey: Uint8Array;
        let pubKeyCompressed: Uint8Array;
        let privKey: Uint8Array;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
          pubKey = await exportPublicKey(kp.publicKey);
          pubKeyCompressed = await exportPublicKey(kp.publicKey, true);
          privKey = await exportPrivateKey(kp.privateKey);
        });

        describe('importPublicKey()', () => {
          test('should import public key and return CryptoKey', async () => {
            const key = await importPublicKey(pubKey, curve);
            expect(key).toBeInstanceOf(CryptoKey);
          });

          test('should import compressed public key and return CryptoKey', async () => {
            const key = await importPublicKey(pubKeyCompressed, curve);
            expect(key).toBeInstanceOf(CryptoKey);
          });
        });

        describe('importKeyPair()', () => {
          test('should import key pair and return both public and private CryptoKey', async () => {
            const pair = await importKeyPair(privKey, pubKey, curve);
            expect(pair.privateKey).toBeInstanceOf(CryptoKey);
            expect(pair.publicKey).toBeInstanceOf(CryptoKey);
          });
        });
      });

      describe('sign()', () => {
        let kp: CryptoKeyPair;
        let data: Uint8Array;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
          data = new TextEncoder().encode('hello world');
        });

        test(`should sign data and return signature as Uint8Array with min ${expectedMinSigSize} bytes`, async () => {
          const sig = await sign(kp.privateKey, data);
          expect(sig).toBeInstanceOf(Uint8Array);
          expect(sig.length).toBeGreaterThanOrEqual(expectedMinSigSize);
        });
      });

      describe('verify()', () => {
        let kp: CryptoKeyPair;
        let data: Uint8Array;
        let sig: Uint8Array;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
          data = new TextEncoder().encode('hello world');
          sig = await sign(kp.privateKey, data);
        });

        test('should verify signature and return true', async () => {
          const ok = await verify(kp.publicKey, sig, data);
          expect(ok).toBeTrue();
        });

        test('should return false is data is incorrect', async () => {
          const ok = await verify(
            kp.publicKey,
            sig,
            new TextEncoder().encode('wrong data')
          );
          expect(ok).toBeFalse();
        });

        test('should return false is public key is incorrect', async () => {
          const wrongKey = await generateKeyPair(curve);
          const ok = await verify(wrongKey.publicKey, sig, data);
          expect(ok).toBeFalse();
        });
      });

      describe('isValidPublicKey()', () => {
        let kp: CryptoKeyPair;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
        });

        test('should return true if public key is valid un-compressed key', async () => {
          const pubKey = await exportPublicKey(kp.publicKey);
          expect(isValidPublicKey(pubKey, curve)).toBeTrue();
        });

        test('should return true if public key is valid compressed key', async () => {
          const pubKey = await exportPublicKey(kp.publicKey, true);
          expect(isValidPublicKey(pubKey, curve)).toBeTrue();
        });

        test('should return false if public key has a wrong size', async () => {
          expect(
            isValidPublicKey(new Uint8Array([4, 1, 2, 3, 4, 5]), curve)
          ).toBeFalse();
        });

        test('should return false if public key starts with a wrong byte', async () => {
          const pubKey = await exportPublicKey(kp.publicKey, true);
          expect(
            isValidPublicKey(new Uint8Array([0, ...pubKey.slice(1)]), curve)
          ).toBeFalse();
        });
      });

      describe('getCurveFromPublicKey()', () => {
        let kp: CryptoKeyPair;

        beforeAll(async () => {
          kp = await generateKeyPair(curve);
        });

        test('should return name of the curve from un-compressed public key', async () => {
          const pubKey = await exportPublicKey(kp.publicKey);
          expect(getCurveFromPublicKey(pubKey)).toEqual(curve);
        });

        test('should return name of the curve from compressed public key', async () => {
          const pubKey = await exportPublicKey(kp.publicKey, true);
          expect(getCurveFromPublicKey(pubKey)).toEqual(curve);
        });
      });
    });
  }
});
