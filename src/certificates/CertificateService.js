import {getAlgorithmParameters, getCrypto} from "pkijs/build/common";
import * as jose from "jose";

export default class CertificateService {
    static async createKeyPair(keyAlg){
        const crypto = getCrypto();
        const algorithm = getAlgorithmParameters(keyAlg, "generatekey");
        return await crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    }

    static publicKeyToJwk(publicKey){
        const crypto = getCrypto();
        return crypto.exportKey("jwk", publicKey);
    }

    static async privateKeyToJoseKey(privateKey){
        const crypto = getCrypto();
        var privatePkcs = await crypto.exportKey("pkcs8", privateKey);
        var pkcsBody = window.btoa(String.fromCharCode(...new Uint8Array(privatePkcs)));
        pkcsBody = pkcsBody.match(/.{1,64}/g).join('\n');
        pkcsBody = (`-----BEGIN PRIVATE KEY-----\n${pkcsBody}\n-----END PRIVATE KEY-----`);
        return await jose.importPKCS8(pkcsBody, "ES256");
    }

    static async createJwtSignature(privateJoseKey, payload, protectedPayload){
        const te = new TextEncoder("utf-8");
        let payloadBuffer;
        if(payload === '') {
            payloadBuffer = te.encode('');
        } else {
            payloadBuffer = te.encode(JSON.stringify(payload));
        }

        const sig =  (await new jose.GeneralSign(payloadBuffer)
            .addSignature(privateJoseKey)
            .setProtectedHeader(protectedPayload)
            .sign()).signatures[0];
        return sig.signature;
    }
}