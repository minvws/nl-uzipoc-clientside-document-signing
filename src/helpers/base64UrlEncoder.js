import {Buffer} from "buffer";

export function base64UrlEncode(input){
    const base64 = Buffer.from(input).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
}

export function base64UrlEncodeObject(input){
    const str = JSON.stringify(input)
    const base64 = Buffer.from(str).toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
}

export function serializePayload(payload){
    if(payload === '') {
        return '';
    } else {
        return base64UrlEncodeObject(payload);
    }
}