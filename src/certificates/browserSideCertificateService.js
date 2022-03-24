import CertificationRequest from "pkijs/build/CertificationRequest";
import {getCrypto} from "pkijs/build/common";
import AttributeTypeAndValue from "pkijs/build/AttributeTypeAndValue";
import * as asn1js from "asn1js";

import GeneralNames from "pkijs/build/GeneralNames";
import GeneralName from "pkijs/build/GeneralName";
import {arrayBufferToString, stringToArrayBuffer} from "pvutils";
import {
    Attribute,
    Certificate, ContentInfo,
    EncapsulatedContentInfo,
    IssuerAndSerialNumber,
    SignedAndUnsignedAttributes,
    SignedData,
    SignerInfo
} from "pkijs";
import Extensions from "pkijs/build/Extensions";
import Extension from "pkijs/build/Extension";

import {base64UrlEncode} from "../helpers/base64UrlEncoder"
import CertificateService from "./CertificateService";
import {arrayBufferToBase64} from "../helpers/bufferHelper";

let hashAlg = "SHA-256";
let signAlg = "ECDSA";

export function formatPEM(pemString)
{
    const PEM_STRING_LENGTH = pemString.length, LINE_LENGTH = 64;
    const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;

    if(wrapNeeded)
    {
        let formattedString = "", wrapIndex = 0;

        for(let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH)
        {
            formattedString += pemString.substring(wrapIndex, i) + "\r\n";
            wrapIndex = i;
        }

        formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
        return formattedString;
    }
    else
    {
        return pemString;
    }
}

export default class BrowserSideCertificateService {
    privateKey;
    publicKey;

    async initAsync(){
        const keyPair = await CertificateService.createKeyPair(signAlg);
        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;
    }

    async createCsr(requestedDomain){
        //region Initial variables
        let sequence = Promise.resolve();

        const pkcs10 = new CertificationRequest();

        //region Get a "crypto" extension
        const crypto = getCrypto();
        if(typeof crypto === "undefined")
            return Promise.reject("No WebCrypto extension found");
        //endregion

        //region Put a static values
        pkcs10.version = 0;
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.6",
            value: new asn1js.PrintableString({ value: "RU" })
        }));
        pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.Utf8String({ value: requestedDomain })
        }));

        const altNames = new GeneralNames({
            names: [
                new GeneralName({
                    type: 2, // dNSName
                    value: requestedDomain
                }),
            ]
        });

        pkcs10.attributes = [];
        //endregion

        //region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
        sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(this.publicKey));
        //endregion

        //region SubjectKeyIdentifier
        sequence = sequence.then(() => crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
            .then(result =>
                {
                    pkcs10.attributes.push(new Attribute({
                        type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
                        values: [(new Extensions({
                            extensions: [
                                new Extension({
                                    extnID: "2.5.29.14",
                                    critical: false,
                                    extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
                                }),
                                new Extension({
                                    extnID: "2.5.29.17",
                                    critical: false,
                                    extnValue: altNames.toSchema().toBER(false)
                                }),
                                new Extension({
                                    extnID: "1.2.840.113549.1.9.7",
                                    critical: false,
                                    extnValue: (new asn1js.PrintableString({ value: "passwordChallenge" })).toBER(false)
                                })
                            ]
                        })).toSchema()]
                    }));
                }
            );
        //endregion

        //region Signing final PKCS#10 request
        sequence = sequence.then(() => pkcs10.sign(this.privateKey, hashAlg), error => Promise.reject(`Error during exporting public key: ${error}`));
        //endregion

        return sequence.then(() =>
        {
            let resultString;
            resultString = `-----BEGIN CERTIFICATE REQUEST-----\r\n`;
            resultString += formatPEM(base64UrlEncode(pkcs10.toSchema().toBER(false)));
            resultString += `\r\n-----END CERTIFICATE REQUEST-----`;
            return resultString;
            // return base64UrlEncode(pkcs10.toSchema().toBER(false));
        }, error => Promise.reject(`Error signing PKCS#10: ${error}`));
    }

    async exportPublicKey(){
        const crypto = getCrypto();
        const keydata = await crypto.exportKey("spki", this.publicKey);
        var keydataS = arrayBufferToString(keydata);
        var keydataB64 = window.btoa(keydataS);
        var keydataB64Pem = formatAsPem(keydataB64);
        return keydataB64Pem;
    }


    createCms(content, certificates) {
        console.log(arrayBufferToBase64(content));

        const startText = '-----BEGIN CERTIFICATE-----';
        const startCert = certificates.indexOf(startText);
        const endCert = certificates.indexOf('-----END CERTIFICATE-----');
        const certificateBase64 = certificates.substr(startCert + startText.length, endCert - startText.length);

        const asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBase64)));
        const certificate = new Certificate({ schema: asn1.result });

        let cmsSignedSimpl;
        let cmsSignedBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CMS_Signed
        let dataBuffer = content;

        let hashAlg = "SHA-256";

        let sequence = Promise.resolve();

        //region Combine all signed extensions
        sequence = sequence.then(
            result =>
            {
                const signedAttr = [];

                signedAttr.push(new Attribute({
                    type: "1.2.840.113549.1.9.3",
                    values: [
                        new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })
                    ]
                })); // contentType

                signedAttr.push(new Attribute({
                    type: "1.2.840.113549.1.9.5",
                    values: [
                        new asn1js.UTCTime({ valueDate: new Date() })
                    ]
                })); // signingTime

                signedAttr.push(new Attribute({
                    type: "1.2.840.113549.1.9.4",
                    values: [
                        new asn1js.OctetString({ valueHex: dataBuffer })
                    ]
                })); // messageDigest

                return signedAttr;
            }
        );
        //endregion

        //region Initialize CMS Signed Data structures and sign it
        sequence = sequence.then(
            result =>
            {
                cmsSignedSimpl = new SignedData({
                    version: 1,
                    encapContentInfo: new EncapsulatedContentInfo({
                        eContentType: "1.2.840.113549.1.7.1" // "data" content type
                    }),
                    signerInfos: [
                        new SignerInfo({
                            version: 1,
                            sid: new IssuerAndSerialNumber({
                                issuer: certificate.issuer,
                                serialNumber: certificate.serialNumber
                            })
                        })
                    ],
                    certificates: [certificate]
                });
                cmsSignedSimpl.signerInfos[0].signedAttrs = new SignedAndUnsignedAttributes({
                    type: 0,
                    attributes: result
                });

                return cmsSignedSimpl.sign(this.privateKey, 0, hashAlg, dataBuffer);
            }
        );
        //endregion

        //region Create final result
        sequence = sequence.then(
            () =>
            {
                const cmsSignedSchema = cmsSignedSimpl.toSchema(true);

                const cmsContentSimp = new ContentInfo({
                    contentType: "1.2.840.113549.1.7.2",
                    content: cmsSignedSchema
                });

                const _cmsSignedSchema = cmsContentSimp.toSchema();

                //region Make length of some elements in "indefinite form"
                _cmsSignedSchema.lenBlock.isIndefiniteForm = true;

                const block1 = _cmsSignedSchema.valueBlock.value[1];
                block1.lenBlock.isIndefiniteForm = true;

                const block2 = block1.valueBlock.value[0];
                block2.lenBlock.isIndefiniteForm = true;

                //endregion

                cmsSignedBuffer = _cmsSignedSchema.toBER(false);
                console.log(cmsSignedBuffer);
            },
            error => Promise.reject(`Erorr during signing of CMS Signed Data: ${error}`)
        ).then(
            () => {
                const signedDataString = String.fromCharCode.apply(null, new Uint8Array(cmsSignedBuffer));
                let resultString;
                resultString = `-----BEGIN CMS-----\r\n`;
                resultString += formatPEM(window.btoa(signedDataString));
                resultString += `\r\n-----END CMS-----`;
                return resultString;
            }
        );
        //endregion

        return sequence;
    }
}
function formatAsPem(str) {
    var finalString = '-----BEGIN PUBLIC KEY-----\n';

    while(str.length > 0) {
        finalString += str.substring(0, 64) + '\n';
        str = str.substring(64);
    }

    finalString = finalString + "-----END PUBLIC KEY-----";

    return finalString;
}