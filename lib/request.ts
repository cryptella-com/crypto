import { uaToHex, base58Decode, base58Encode, textEncode } from '@cryptella/utils/encoding';
import { parseHeaderValueParams, serializeHeaderParams } from '@cryptella/utils/headers';
import { streamToUint8Array } from '@cryptella/utils/streams';
import { exportPublicKey, importPublicKey, sign, verify } from './ecdsa.js';

export const MAX_TIME_SKEW_SEC = 20;

export const SIGNATURE_TYPE = 'ESCDA-SHA256-B58';

export type Body = ReadableStream | ArrayBuffer | Uint8Array | Blob | string;

export interface ISignRequestOptions {
  signedHeaders?: string[];
  time?: number;
}

export interface IVerifyRequestOptions {
  authorization?: string;
  bodyHash?: string;
  maxTimeSkewSec?: number;
}

export interface RequestLike {
  body: BufferSource | string;
  headers: Record<string, string>;
  method: string;
}

export async function signRequest(
  keyPair: CryptoKeyPair,
  method: string,
  url: string,
  headersToSign: [ string, string ][],
  body: Body,
  options: ISignRequestOptions = {}
) {
  const time = timeToSeconds(options.time || Date.now());
  const canonical = buildCanonical(
    method,
    url,
    headersToSign,
    await hashRequestBody(body),
    time,
  );
  const sig = base58Encode(
    await sign(keyPair.privateKey, textEncode(canonical))
  );
  const pubkey = base58Encode(await exportPublicKey(keyPair.publicKey));
  const params = serializeHeaderParams({
    pubkey, 
    headers: headersToSign.map(([ k ]) => k).join(','),
    time: String(time),
    sig,
  });
  return {
    authorization: `${SIGNATURE_TYPE} ${params}`,
  };
}

export async function verifyRequest(
  method: string,
  url: string,
  headers: Record<string, string>,
  body: Body,
  options: IVerifyRequestOptions = {}
) {
  const authorization = options.authorization || headers['authorization'] || ';'
  const { value, params } = parseHeaderValueParams(authorization);
  if (value === SIGNATURE_TYPE) {
    if (!params?.pubkey || !params?.sig || !params?.time) {
      return {
        error: 'Malformatted signature header.',
        ok: false,
      };
    }
    const maxTimeSkewSec = options.maxTimeSkewSec || MAX_TIME_SKEW_SEC;
    if (Math.abs(Math.floor(Date.now() / 1000) - +params.time) > maxTimeSkewSec) {
      return {
        error: `Time skew too large.`,
        ok: false,
      };
    }
    let bodyHash = options.bodyHash;
    if (!bodyHash) {
      bodyHash = await hashRequestBody(body);
    }
    const canonical = buildCanonical(
      method,
      url,
      (params.headers?.split(',') || []).map((k) => [ k, headers[k] || '' ]),
      bodyHash,
      +params.time,
    );
    let ok: boolean = false;
    try {
      ok = await verify(
        await importPublicKey(base58Decode(params.pubkey!)),
        base58Decode(params.sig!),
        textEncode(canonical)
      );
    } catch (err) {
      return {
        error: 'Unable to verify signature.',
        errorReason: err,
        ok: false,
      };
    }
    return {
      ok,
      publicKey: ok ? params.pubkey : void 0,
    };
  }
  return {
    error: 'Unknown signature type.',
    ok: false,
  };
}

export async function hashRequestBody(
  body: ReadableStream | ArrayBuffer | Uint8Array | Blob | string,
  digest: string = 'SHA-256'
) {
  if (body instanceof Blob) {
    body = new Uint8Array(await body.arrayBuffer());
  } else if (body instanceof ArrayBuffer) {
    body = new Uint8Array(body);
    console.log('???X', body)
  } else if (body instanceof ReadableStream) {
    body = await streamToUint8Array(body);
    console.log('???', body)
  } else if (typeof body === 'string') {
    body = textEncode(body);
  }
  return uaToHex(new Uint8Array(await crypto.subtle.digest(digest, body)));
}

function buildCanonical(
  method: string,
  url: string,
  headersToSign: [ string, string ][],
  bodyHash: string,
  time: number
) {
  return [
    method,
    url,
    ...headersToSign
      .filter(([ k ]) => !!k)
      .map(([ k, v ]) => {
        return `${k}: ${v}`;
      }),
    bodyHash,
    String(time),
  ].join('\n');
}

function timeToSeconds(time: number) {
  if (time > (Date.now() / 1000) * 2) {
    // time is in ms
    return Math.floor(time / 1000);
  }
  return time;
}
