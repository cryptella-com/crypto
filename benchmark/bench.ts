import { benchmark } from './helpers';
import * as ED from '@noble/ed25519';
import * as ECDSA from '../lib/ecdsa';

const data = new TextEncoder().encode('hello world');

// ECDSA
const ecdsaKeyPair = await ECDSA.generateKeyPair();
const ecdsaPubKey = await ECDSA.exportPublicKey(ecdsaKeyPair.publicKey);
const ecdsaSig = await ECDSA.sign(ecdsaKeyPair.privateKey, data);

// ED25519
const edPrivKey = ED.utils.randomPrivateKey();
const edPubKey = await ED.getPublicKeyAsync(edPrivKey);
const edSig = await ED.signAsync(data, edPrivKey);

await benchmark('Sign', (bench) => {
  bench
    .add('ECDSA - sign', async () => {
      await ECDSA.sign(ecdsaKeyPair.privateKey, data);
    })
    .add('@noble/ed25519 - sign', async () => {
      await ED.signAsync(data, edPrivKey); 
    });
});

await benchmark('Verify', (bench) => {
  bench
    .add('ECDSA - verify', async () => {
      await ECDSA.verify(ecdsaKeyPair.publicKey, ecdsaSig, data);
    })
    .add('@noble/ed25519 - verify', async () => {
      await ED.verifyAsync(edSig, data, edPubKey); 
    });
});
