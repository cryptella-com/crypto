import { getCurveFromPublicKey } from './ecdsa.js';

export async function generateKey() {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportKey(key: CryptoKey) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importKey(key: Uint8Array) {
  return crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-GCM',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function deriveWrappingKey(
  keyPair: CryptoKeyPair,
  pubKey: Uint8Array
) {
  const curve = getCurveFromPublicKey(pubKey) || 'P-256';
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const ecdhPrivateKey = await crypto.subtle.importKey(
    'jwk',
    {
      ...jwk,
      key_ops: ['deriveKey', 'deriveBits'],
    },
    {
      name: 'ECDH',
      namedCurve: curve,
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  const ecdhPublicKey = await crypto.subtle.importKey(
    'raw',
    pubKey,
    {
      name: 'ECDH',
      namedCurve: curve,
    },
    true,
    []
  );
  return crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: ecdhPublicKey,
    },
    ecdhPrivateKey,
    {
      name: 'AES-KW',
      length: 256,
    },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

export async function wrapKey(
  keyToWrap: CryptoKey,
  senderKeyPair: CryptoKeyPair,
  recipientPubKey: Uint8Array
) {
  const wrapKey = await deriveWrappingKey(senderKeyPair, recipientPubKey);
  return new Uint8Array(await crypto.subtle.wrapKey('raw', keyToWrap, wrapKey, {
    name: 'AES-KW',
  }));
}

export async function unwrapKey(
  wrappedKey: Uint8Array,
  recipientKeyPair: CryptoKeyPair,
  senderPubKey: Uint8Array
) {
  const unwrapKey = await deriveWrappingKey(recipientKeyPair, senderPubKey);
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    unwrapKey,
    {
      name: 'AES-KW',
    },
    'AES-GCM',
    true,
    ['decrypt', 'encrypt']
  );
}

export async function encrypt(key: CryptoKey, data: Uint8Array) {
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    data
  ));
  return {
    encrypted,
    iv,
  };
}

export async function decrypt(
  key: CryptoKey,
  data: Uint8Array,
  iv: Uint8Array
) {
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    data
  ));
}
