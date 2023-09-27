import { base64ToArrayBuffer, arrayBufferToBase64 } from './helpers';

export type TCurveName = 'P-256' | 'P-384' | 'P-521';

export type THashName = 'SHA-256' | 'SHA-384' | 'SHA-521';

export const ALG = 'ECDSA';

export const CURVES: TCurveName[] = ['P-256', 'P-384', 'P-521'];

export const PUB_KEY_LEN: Record<TCurveName, number> = {
  'P-256': 65,
  'P-384': 97,
  'P-521': 133,
};

export async function generateKeyPair(curve: TCurveName = 'P-256') {
  return crypto.subtle.generateKey(
    {
      name: ALG,
      namedCurve: curve,
    },
    true,
    ['sign', 'verify']
  );
}

export async function exportPublicKey(
  publicKey: CryptoKey,
  compress: boolean = false
) {
  const pubKey = new Uint8Array(
    await crypto.subtle.exportKey('raw', publicKey)
  );
  if (compress) {
    const len = (pubKey.length - 1) / 2;
    return new Uint8Array([
      pubKey[2 * len] % 2 ? 3 : 2,
      ...pubKey.slice(1, len + 1),
    ]);
  }
  return pubKey;
}

export async function exportPrivateKey(privateKey: CryptoKey) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  return base64ToArrayBuffer(jwk.d!, true);
}

export async function importPublicKey(
  publicKey: Uint8Array,
  curve: TCurveName = 'P-256'
) {
  return crypto.subtle.importKey(
    'raw',
    publicKey,
    {
      name: ALG,
      namedCurve: curve,
    },
    true,
    ['verify']
  );
}

export async function importKeyPair(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  curve: TCurveName = 'P-256'
): Promise<CryptoKeyPair> {
  const importedPublicKey = await importPublicKey(publicKey, curve);
  const jwk = await crypto.subtle.exportKey('jwk', importedPublicKey);
  const importedPrivateKey = await crypto.subtle.importKey(
    'jwk',
    {
      ...jwk,
      d: arrayBufferToBase64(privateKey, true),
      key_ops: ['sign'],
    },
    {
      name: ALG,
      namedCurve: curve,
    },
    true,
    ['sign']
  );
  return {
    privateKey: importedPrivateKey,
    publicKey: importedPublicKey,
  };
}

export async function sign(
  privateKey: CryptoKey,
  data: Uint8Array,
  hashName: THashName = 'SHA-256'
) {
  return new Uint8Array(
    await crypto.subtle.sign(
      {
        name: ALG,
        hash: { name: hashName },
      },
      privateKey,
      data
    )
  );
}

export async function verify(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
  hashName: THashName = 'SHA-256'
) {
  return crypto.subtle.verify(
    {
      name: ALG,
      hash: { name: hashName },
    },
    publicKey,
    signature,
    data
  );
}

export function getCurveFromPublicKey(publicKey: Uint8Array) {
  const len = publicKey.length;
  for (let curve in PUB_KEY_LEN) {
    const curveLen = PUB_KEY_LEN[curve as TCurveName];
    if (len === curveLen || len === (curveLen - 1) / 2 + 1) {
      return curve;
    }
  }
  return null;
}

export function isValidPublicKey(
  publicKey: Uint8Array,
  curve: TCurveName = 'P-256'
) {
  switch (publicKey[0]) {
    case 4:
      // un-compressed
      return publicKey.length === PUB_KEY_LEN[curve];
    case 2:
    case 3:
      // compressed
      return publicKey.length === (PUB_KEY_LEN[curve] - 1) / 2 + 1;
    default:
      return false;
  }
}
