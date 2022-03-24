import AcmeClient from "./acmeClient";
import * as jose from "jose";
import CertificateService from "../certificates/CertificateService";

export default class AcmeService {

    async fetchAcmeCertificate(domain, csr, jwt, publicKey){
        const acmeService = new AcmeClient();
        await acmeService.initAsync();

        const accountKeyPair = await CertificateService.createKeyPair("ECDSA");
        const publicJwk = await CertificateService.publicKeyToJwk(accountKeyPair.publicKey);
        const accountJoseKey = await CertificateService.privateKeyToJoseKey(accountKeyPair.privateKey);
        const signFnAsync = (payload, protectedPayload) =>
            CertificateService.createJwtSignature(
                accountJoseKey,
                payload,
                protectedPayload);

        await acmeService.newAccount(
            publicJwk,
            signFnAsync);

        const order = await acmeService.newOrder(domain, signFnAsync);
        const challengeUrl = order.authorizations[0];
        const finalizeUrl = order.finalize;

        const challenges = await acmeService.fetchChallenge(challengeUrl, signFnAsync);
        const challenge = challenges.challenges.filter(c => c.type == "trusted-jwt-01")[0];
        const challengeNotifyUrl = challenge.url;

        const keyAuthorization = await jose.calculateJwkThumbprint(publicJwk, "sha256");
        const authUrl = challenge.url.slice(challenge.url.indexOf("/chall-v3/") + 10);

        await acmeService.updateJwt(authUrl, jwt, publicKey, keyAuthorization, signFnAsync)

        await acmeService.notifyAuthorization(challengeNotifyUrl, signFnAsync);

        console.log("Waiting 3 sec");
        await new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                acmeService.fetchChallenge(challengeUrl, signFnAsync)
                    .then(challenges => {
                        if (challenges.status === "valid") {
                            clearInterval(interval);
                            resolve();
                            console.log("valid!");
                        }

                    });
            }, 3000);
        });

        const finalizeResponse = await acmeService.finalize(finalizeUrl, csr, signFnAsync);
        const certificateUrl = finalizeResponse.certificate;
        return await acmeService.downloadCertificate(certificateUrl, signFnAsync);
    }
}