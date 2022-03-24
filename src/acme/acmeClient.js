import {serializePayload, base64UrlEncodeObject} from "../helpers/base64UrlEncoder";
import {arrayBufferToBase64} from "../helpers/bufferHelper";
import {Buffer} from "buffer";

export default class AcmeClient {
    nonce;
    kid;

    async initAsync(){
        this.nonce = await new Promise((resolve,reject)=>{
            var xhr = new XMLHttpRequest();
            xhr.open("HEAD", "http://localhost:4001/acme/new-nonce", true);
            xhr.onload = function(){
                resolve(this.getResponseHeader("replay-nonce"));
            }
            xhr.send();
        });
    }

    async newAccount(publicJwk, signFnAsync){
        var url = "http://localhost:4001/acme/new-acct";
        var protectedPayload = {
            alg: 'ES256',
            nonce: this.nonce,
            url: url,
            jwk: publicJwk
        };
        var payload = {
            'termsOfServiceAgreed': true,
            'contacts': ['gerbrandb@gmail.com']
        };
        var xhr = await this.request(url, payload, protectedPayload, signFnAsync);
        this.kid = xhr
            .getResponseHeader('location');
    }

    async updateJwt(authUrl, jwt, publicKey, token, signFnAsync){
        const url = "http://localhost:4001/acme/jwt-v3/" + authUrl;
        const protectedPayload = {
            alg: 'ES256',
            nonce: this.nonce,
            url: url,
            kid: this.kid
        };
        const payload = {
            "jwt": jwt,
            "publicKey": Buffer.from(publicKey).toString('base64'),
            "token": token,
        };
        await this.request(url, payload, protectedPayload, signFnAsync);
    }


    async newOrder(requestedDomain, signFnAsync){
        const url = "http://localhost:4001/acme/new-order";
        const protectedPayload = {
            alg: 'ES256',
            nonce: this.nonce,
            url: url,
            kid: this.kid
        };
        const payload = {
            "identifiers": [
                // {"type": "dns", "value": requestedDomain}
                {"type": "jwt", "value": requestedDomain}
            ]
        };
        const xhr = await this.request(url, payload, protectedPayload, signFnAsync);
        return JSON.parse(xhr.responseText);
    }

    fetchChallenge(challengeUrl, signFnAsync){
        return this.postAsGet(challengeUrl, signFnAsync);
    }

    postAsGet(url, signFnAsync, parseJson = true){
        return this.post(url, '', signFnAsync, parseJson);
    }

    postEmptyObject(url, signFnAsync){
        return this.post(url, {}, signFnAsync);
    }

    async post(url, payload, signFnAsync, parseJson = true){
        const protectedPayload = {
            alg: 'ES256',
            nonce: this.nonce,
            url: url,
            kid: this.kid
        };
        const xhr = await this.request(url, payload, protectedPayload, signFnAsync);
        if(parseJson)
            return JSON.parse(xhr.responseText);
        return xhr.responseText;
    }

    notifyAuthorization(notifyUrl, signFnAsync){
        return this.postEmptyObject(notifyUrl, signFnAsync);
    }

    async finalize(finalizeUrl, csr, signFnAsync){
        csr = csr.replace('-----BEGIN CERTIFICATE REQUEST-----', '');
        csr = csr.replace('-----END CERTIFICATE REQUEST-----', '');
        csr = csr.replaceAll('\r', '');
        csr = csr.replaceAll('\n', '');
        csr = csr
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/\=+$/, '');
        var protectedPayload = {
            alg: 'ES256',
            nonce: this.nonce,
            url: finalizeUrl,
            kid: this.kid
        };
        const payload = {
            csr: csr
        }
        const xhr = await this.request(finalizeUrl, payload, protectedPayload, signFnAsync);
        return JSON.parse(xhr.responseText);
    }

    async downloadCertificate(certificateUrl, signFnAsync){
        return this.postAsGet(certificateUrl, signFnAsync, false);
    }

    async request(url, payload, protectedPayload, signFnAsync){
        const jsonRequest = {
            "protected": base64UrlEncodeObject(protectedPayload),
            "payload": serializePayload(payload),
            "signature": await signFnAsync(payload, protectedPayload),
        }
        const response = await new Promise((resolve, reject) => {
            var xhr = new XMLHttpRequest();
            xhr.open("POST", url, true);
            xhr.setRequestHeader('Content-Type', 'application/jose+json');
            xhr.onload = function(){
                resolve(this);
            }
            xhr.send(JSON.stringify(jsonRequest));
        });
        this.nonce = response.getResponseHeader("replay-nonce");
        return response;
    }
}