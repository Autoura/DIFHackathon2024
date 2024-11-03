import {DidJwk} from "@web5/dids";
import nacl from "tweetnacl";
import sodium from 'libsodium-wrappers';

let my_did = null;

// This JavasScript based demo will work with ANY Autoura.me DID
// 1) Put the DID in test_did
// 2) Go to the DID Document for this DID - e.g. put the DID in the DIF Universal Resolver https://resolver.identity.foundation/ and hit "get document". Find the verification methods section of the DID Document response
// 3) Copy the full X25519KeyAgreementKey2020 section into test_did_keyagreement
// 4) Set the three service URLs (as these are DID specific). You can get these from the DID Document
// 5) Thats it. If setting an Autoura.me DID this code now can access that DID's preferences, location, and that DID can now receive DIDComm messages from this demo code. (Does rely on the DID owner, i.e. the consumer, giving the right permissions too, via the Autoura Connect app)

let test_did = "did:web:did.autoura.me:api:did:profile:eEJ6QzZpVUZSVWhmZ3A2Y1Y4UnAwREdkZkJrcytRZUIxZ2VERkdTVWhMeEZmYVVkNnQxRnhYNjAwOGxjZGMzVm5tU1EwQStxdkNq..:..QXlWRG1XcTM1RHp3MHExTUluN1B3VkNOaXViRkdTZkVKTWs2emtjczhXQkI0TnZDMmFIM0VxNEtKSTZNQVF3SzR4MU9uY2EyUFQ0..:..RmpHRk9iZHNsMy9od2JSSnBUQ2QzZFNZNTdKNE54UWdKSzdUWU5KK3Qx";
let test_did_keyagreement = {
    "id": "#key-3",
    "type": "X25519KeyAgreementKey2020",
    "controller": "did:web:did.autoura.me:api:did:profile:eEJ6QzZpVUZSVWhmZ3A2Y1Y4UnAwREdkZkJrcytRZUIxZ2VERkdTVWhMeEZmYVVkNnQxRnhYNjAwOGxjZGMzVm5tU1EwQStxdkNq..:..QXlWRG1XcTM1RHp3MHExTUluN1B3VkNOaXViRkdTZkVKTWs2emtjczhXQkI0TnZDMmFIM0VxNEtKSTZNQVF3SzR4MU9uY2EyUFQ0..:..RmpHRk9iZHNsMy9od2JSSnBUQ2QzZFNZNTdKNE54UWdKSzdUWU5KK3Qx",
    "publicKeyMultibase": "zirUUZ12p43dtpFv3ri4euvMfcYXSpDGa5ZKWRJJgLQy"
}
let test_did_service_url = {
    'preferences': "https://api.autoura.com/api/did/services/profile/eEJ6QzZpVUZSVWhmZ3A2Y1Y4UnAwREdkZkJrcytRZUIxZ2VERkdTVWhMeEZmYVVkNnQxRnhYNjAwOGxjZGMzVm5tU1EwQStxdkNq../..QXlWRG1XcTM1RHp3MHExTUluN1B3VkNOaXViRkdTZkVKTWs2emtjczhXQkI0TnZDMmFIM0VxNEtKSTZNQVF3SzR4MU9uY2EyUFQ0../..RmpHRk9iZHNsMy9od2JSSnBUQ2QzZFNZNTdKNE54UWdKSzdUWU5KK3Qx/preferences",
    'location': "https://api.autoura.com/api/did/services/profile/eEJ6QzZpVUZSVWhmZ3A2Y1Y4UnAwREdkZkJrcytRZUIxZ2VERkdTVWhMeEZmYVVkNnQxRnhYNjAwOGxjZGMzVm5tU1EwQStxdkNq../..QXlWRG1XcTM1RHp3MHExTUluN1B3VkNOaXViRkdTZkVKTWs2emtjczhXQkI0TnZDMmFIM0VxNEtKSTZNQVF3SzR4MU9uY2EyUFQ0../..RmpHRk9iZHNsMy9od2JSSnBUQ2QzZFNZNTdKNE54UWdKSzdUWU5KK3Qx/location",
    "messages": "https://api.autoura.com/api/did/services/profile/eEJ6QzZpVUZSVWhmZ3A2Y1Y4UnAwREdkZkJrcytRZUIxZ2VERkdTVWhMeEZmYVVkNnQxRnhYNjAwOGxjZGMzVm5tU1EwQStxdkNq../..QXlWRG1XcTM1RHp3MHExTUluN1B3VkNOaXViRkdTZkVKTWs2emtjczhXQkI0TnZDMmFIM0VxNEtKSTZNQVF3SzR4MU9uY2EyUFQ0../..RmpHRk9iZHNsMy9od2JSSnBUQ2QzZFNZNTdKNE54UWdKSzdUWU5KK3Qx/message"
};

export const didTools = {

    async create_my_did() {
        const didJwk = await DidJwk.create();
        my_did = await didJwk.export();

        return my_did;
    },

    get_my_did() {
        return my_did;
    },

    get_test_did() {
        return test_did;
    },

    get_test_did_keyagreement_kid() {
      return test_did_keyagreement.id;
    },

    get_test_did_keyagreement_public_key() {
        return test_did_keyagreement.publicKeyMultibase;
    },

    get_test_did_service_url(style) {
        return test_did_service_url[style];
    },

    encodeMultibase(bytes, encoding) {
        if (encoding === 'base58btc') {
            const base58String = this.base58Encode(bytes);
            return `z${base58String}`;
        } else {
            throw new Error('Unsupported multibase encoding');
        }
    },

    decodeMultibase(multibaseString) {
        if (multibaseString.startsWith('z')) {
            const base58String = multibaseString.slice(1);
            return this.decodeBase58(base58String);
        } else {
            throw new Error('Unsupported multibase encoding');
        }
    },

    base64urlEncode(input) {
        // Check if the input is a Uint8Array or a string
        if (input instanceof Uint8Array) {
            // Convert Uint8Array to a string first before encoding
            input = String.fromCharCode.apply(null, input);
        }

        // Now Base64 encode the string
        return btoa(input)
            .replace(/\+/g, "-")  // Replace '+' with '-'
            .replace(/\//g, "_")  // Replace '/' with '_'
            .replace(/=+$/, "");  // Strip padding '='
    },

    base64urlDecode(base64String) {
        const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding)
            .replace(/-/g, "+")
            .replace(/_/g, "/");
        const rawData = atob(base64);
        return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
    },

    decodeBase64(base64String) {
        const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding)
            .replace(/-/g, "+")
            .replace(/_/g, "/");

        // Decode the base64 string
        const rawData = atob(base64);

        // Convert the decoded string into a Uint8Array (binary data)
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; i++) {
            outputArray[i] = rawData.charCodeAt(i);
        }

        return outputArray;
    },

    base58Encode(bytes) {
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let encoded = '';
        let num = BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
        while (num > 0) {
            const remainder = num % 58n;
            num = num / 58n;
            encoded = alphabet[remainder] + encoded;
        }
        for (const byte of bytes) {
            if (byte === 0) {
                encoded = '1' + encoded;
            } else {
                break;
            }
        }
        return encoded;
    },

    decodeBase58(base58) {

        /* global BigInt */

        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        const base58Chars = alphabet.split('');

        let num = BigInt(0);
        const base = BigInt(58);

        // Iterate over each character in the base58 string
        for (let i = 0; i < base58.length; i++) {
            const char = base58[i];
            const index = base58Chars.indexOf(char);

            if (index === -1) {
                throw new Error(`Invalid character '${char}' in Base58 string.`);
            }

            num = num * base + BigInt(index);
        }

        // Convert BigInt to a hexadecimal string
        let hex = num.toString(16);

        // Ensure the hex string has an even number of digits
        if (hex.length % 2 !== 0) {
            hex = '0' + hex;
        }

        // Convert the hex string to a Uint8Array (binary data)
        const byteArray = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        // Add leading zero bytes for each leading '1' in the base58 string
        let leadingOnes = 0;
        for (let i = 0; i < base58.length && base58[i] === '1'; i++) {
            leadingOnes++;
        }

        // Prepend leading zero bytes to the byte array
        const leadingZeros = new Uint8Array(leadingOnes).fill(0);

        // Return the Uint8Array
        return new Uint8Array([...leadingZeros, ...byteArray]);
    },

    // Method to create a JWT using Ed25519 (EdDSA)
    async createJWT(privateJwk, did, audience, expiresIn = 3600) {
        try {
            // Step 1: Create JWT Header
            const header = {
                alg: "EdDSA",  // Algorithm set to EdDSA for Ed25519 keys
                typ: "JWT",
                kid: privateJwk.kid
            };

            // Step 2: Create JWT Payload
            const issuedAt = Math.floor(Date.now() / 1000);
            const expiration = issuedAt + expiresIn;

            const payload = {
                iss: did,
                sub: did,
                aud: audience,
                iat: issuedAt,
                exp: expiration
            };

            // Step 3: Base64Url encode Header and Payload
            const encodedHeader = didTools.base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
            const encodedPayload = didTools.base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));

            // Step 4: Create the unsigned token (Header.Payload)
            const unsignedToken = `${encodedHeader}.${encodedPayload}`;

            // Step 5: Decode the private key ('d') and public key ('x') from Base64URL to Uint8Array
            const privateKeyBytes = didTools.decodeBase64(privateJwk.d);  // 32-byte private key
            const publicKeyBytes = didTools.decodeBase64(privateJwk.x);   // 32-byte public key

            // Concatenate private and public key to form the full 64-byte key
            const fullPrivateKey = new Uint8Array(64);
            fullPrivateKey.set(privateKeyBytes);
            fullPrivateKey.set(publicKeyBytes, 32);  // Add public key after the private key

            // Ensure fullPrivateKey is a Uint8Array of 64 bytes
            if (fullPrivateKey.length !== 64) {
                throw new Error("The combined private key must be 64 bytes.");
            }

            // Step 6: Sign the token using tweetnacl (sign the unsigned token as Uint8Array)
            const signature = nacl.sign.detached(new TextEncoder().encode(unsignedToken), fullPrivateKey);

            // Step 7: Base64Url encode the signature
            const encodedSignature = didTools.base64urlEncode(signature);

            // Step 8: Return the complete JWT (Header.Payload.Signature)
            return `${unsignedToken}.${encodedSignature}`;
        } catch (error) {
            console.error("Error creating JWT:", error);
            throw error;
        }
    },

    async sendDIDComm(content, my_did) {
        try {

            this.response = {};

            // Step 1: Create the message
            const message = {
                "type": "https://didcomm.org/basicmessage/2.0/message",
                "from": my_did.uri,
                "to": [didTools.get_test_did()],
                "id": "1234567890",
                "body": {
                    "content": content
                }
            };

            // Step 2: Prepare the protected header and payload for signing
            const signingProtectedHeader = {
                alg: "EdDSA",  // Algorithm for Ed25519
                typ: "application/didcomm-signed+json"
            };

            const signingProtectedHeaderEncoded = didTools.base64urlEncode(JSON.stringify(signingProtectedHeader));
            const messagePayloadEncoded = didTools.base64urlEncode(JSON.stringify(message));
            const signingInput = `${signingProtectedHeaderEncoded}.${messagePayloadEncoded}`;

            // Step 3: Sign the message using Ed25519 with libsodium
            const privateKeyJwk = my_did.privateKeys[0]; // Your Ed25519 private key in JWK format
            const signatureBase64url = await this.signMessageEd25519(signingInput, privateKeyJwk);

            // Step 4: Build the final signed message
            const signedMessage = {
                protected: signingProtectedHeaderEncoded,
                payload: messagePayloadEncoded,
                signature: signatureBase64url
            };

            // Step 5: Derive the shared secret using X25519
            const recipientPublicKeyMultibase = didTools.get_test_did_keyagreement_public_key();
            const recipientPublicKeyBytes = didTools.decodeMultibase(recipientPublicKeyMultibase);

            // Generate an ephemeral key pair for X25519
            const ephemeralKeyPair = await this.generateX25519KeyPair();
            const ephemeralPublicKeyBytes = ephemeralKeyPair.publicKey;

            // Derive the shared secret using X25519
            const sharedSecret = await this.x25519(ephemeralKeyPair.privateKey, recipientPublicKeyBytes);

            // Step 6: Derive the KEK using Concat KDF
            const kekBits = await this.deriveKEK(sharedSecret, 256, 'A256KW');

            // Import the KEK for AES-KW
            const kekKey = await crypto.subtle.importKey(
                "raw",
                kekBits,
                {name: "AES-KW"},
                false,
                ["wrapKey", "unwrapKey"]
            );

            // Step 7: Derive the symmetric key (CEK) for AES-GCM encryption
            const symmetricKey = await crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256  // AES-256
                },
                true,
                ["encrypt", "decrypt"]
            );

            // Step 8: AES Key Wrap the CEK using the derived KEK
            const wrappedKey = await this.aesKeyWrap(kekKey, symmetricKey);

            // After wrapping the CEK, convert wrappedKey to Uint8Array
            const wrappedKeyUint8 = new Uint8Array(wrappedKey);

            // Step 9: Encrypt the signed message using AES-GCM
            const iv = crypto.getRandomValues(new Uint8Array(12));  // IV for AES-GCM
            const messageToEncrypt = JSON.stringify(signedMessage);  // Signed message from earlier steps

            const encoder = new TextEncoder();
            const messageBytes = encoder.encode(messageToEncrypt);

            const encryptedContentBuffer = await crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                symmetricKey,
                messageBytes
            );

            const encryptedContentArray = new Uint8Array(encryptedContentBuffer);
            const tagLength = 16;  // AES-GCM tag length
            const ciphertext = encryptedContentArray.slice(0, -tagLength);
            const tag = encryptedContentArray.slice(-tagLength);

            // Convert the ephemeral public key to Base64URL for inclusion in JWK format
            const ephemeralPublicKeyBase64url = didTools.base64urlEncode(ephemeralPublicKeyBytes);

            // Create the ephemeral public key JWK object
            const ephemeralPublicKeyJwk = {
                kty: "OKP",  // Key type for X25519
                crv: "X25519",  // Curve for X25519 key agreement
                x: ephemeralPublicKeyBase64url  // Base64URL encoded public key bytes
            };

            const protectedHeader = {
                alg: "X25519+A256KW",
                enc: "A256GCM",
                typ: "application/didcomm-encrypted+json",
                epk: ephemeralPublicKeyJwk
            };

            const protectedHeaderEncoded = didTools.base64urlEncode(JSON.stringify(protectedHeader));

            // Build the final encrypted payload
            const encryptedPayload = {
                protected: protectedHeaderEncoded,
                recipients: [{
                    header: {
                        kid: didTools.get_test_did_keyagreement_kid(),
                        alg: "X25519+A256KW"
                    },
                    encrypted_key: didTools.base64urlEncode(wrappedKeyUint8)  // Base64URL encode the AES-wrapped symmetric key
                }],
                ciphertext: didTools.base64urlEncode(ciphertext),  // Base64URL encoded ciphertext
                iv: didTools.base64urlEncode(iv),  // Base64URL encoded IV
                tag: didTools.base64urlEncode(tag)  // Base64URL encoded authentication tag
            };

            // Step 11: Send the encrypted message to the service
            const serviceUrl = didTools.get_test_did_service_url('messages');
            const response = await fetch(serviceUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/didcomm-encrypted+json"
                },
                body: JSON.stringify(encryptedPayload)
            });

            return response.json();

        } catch (error) {
            console.error('Error sending DIDComm message:', error);
        }
    },

    packUInt32BE(value) {
        const buffer = new ArrayBuffer(4);
        const view = new DataView(buffer);
        view.setUint32(0, value, false); // false for big-endian
        return new Uint8Array(buffer);
    },

    concatenateArrays(...arrays) {
        let totalLength = 0;
        arrays.forEach(arr => {
            totalLength += arr.length;
        });
        const result = new Uint8Array(totalLength);
        let offset = 0;
        arrays.forEach(arr => {
            result.set(arr, offset);
            offset += arr.length;
        });
        return result;
    },

    async concatKdf(sharedSecret, keyLengthBits, algorithmId) {
        const hashAlg = 'SHA-256';
        const hashLengthBits = 256;
        const reps = Math.ceil(keyLengthBits / hashLengthBits);
        const keyLengthBytes = keyLengthBits / 8;

        // Convert AlgorithmID to bytes
        const encoder = new TextEncoder();
        const algorithmIdBytes = encoder.encode(algorithmId);
        const algorithmIdLength = this.packUInt32BE(algorithmIdBytes.length); // 4-byte big-endian

        // SuppPubInfo: Key length in bits, big-endian
        const suppPubInfo = this.packUInt32BE(keyLengthBits); // 4-byte big-endian

        // Construct otherInfo: AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo || SuppPrivInfo
        // For simplicity, PartyUInfo, PartyVInfo, SuppPrivInfo are empty
        const otherInfo = this.concatenateArrays(algorithmIdLength, algorithmIdBytes, suppPubInfo);

        let derivedKey = new Uint8Array();
        for (let i = 1; i <= reps; i++) {
            const counter = this.packUInt32BE(i); // 4-byte big-endian
            const dataToHash = this.concatenateArrays(counter, sharedSecret, otherInfo);
            const hashBuffer = await crypto.subtle.digest(hashAlg, dataToHash);
            const hashArray = new Uint8Array(hashBuffer);
            derivedKey = this.concatenateArrays(derivedKey, hashArray);
        }

        return derivedKey.slice(0, keyLengthBytes);
    },

    async generateX25519KeyPair() {
        const keyPair = nacl.box.keyPair(); // Generates a key pair using X25519

        return {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.secretKey
        };
    },

    x25519(privateKey, publicKey) {
        return nacl.scalarMult(privateKey, publicKey);
    },

    async signMessageEd25519(message, privateKeyJwk) {
        // Load sodium
        await sodium.ready;

        // Decode the private scalar from JWK (base64url decode 'd')
        const privateScalarBytes = sodium.from_base64(privateKeyJwk.d, sodium.base64_variants.URLSAFE_NO_PADDING);

        // Decode the public key from JWK (base64url decode 'x')
        const publicKeyBytes = sodium.from_base64(privateKeyJwk.x, sodium.base64_variants.URLSAFE_NO_PADDING);

        // Reconstruct the full 64-byte private key (private scalar + public key)
        const fullPrivateKey = new Uint8Array(64);
        fullPrivateKey.set(privateScalarBytes);
        fullPrivateKey.set(publicKeyBytes, 32); // Append public key after the private scalar

        // Convert the message to a Uint8Array
        const messageBytes = new TextEncoder().encode(message);

        // Sign the message using sodium's Ed25519 signing function
        const signature = sodium.crypto_sign_detached(messageBytes, fullPrivateKey);

        // Encode the signature in base64url format for sending
        const signatureBase64url = sodium.to_base64(signature, sodium.base64_variants.URLSAFE_NO_PADDING);

        return signatureBase64url;
    },

    async deriveKEK(sharedSecret, keyLengthBits, algorithmId) {
        return await this.concatKdf(sharedSecret, keyLengthBits, algorithmId);
    },

    async aesKeyWrap(kekKey, cekKey) {
        return await crypto.subtle.wrapKey(
            "raw", // Export format
            cekKey,
            kekKey,
            "AES-KW" // AES Key Wrap algorithm
        );
    },

}