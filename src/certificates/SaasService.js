import {arrayBufferToBase64} from "../helpers/bufferHelper";

function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

export default class SaasService {
    async createCsr(jwt){
        return await new Promise((resolve, reject) => {
            var xhr = new XMLHttpRequest();
            xhr.open("GET",  "http://localhost:8002/csr", true);
            xhr.setRequestHeader('Authorization', jwt);
            xhr.onload = function(){
                let pemCsr = window.atob(JSON.parse(this.responseText).csr);
                resolve(pemCsr);
            }
            xhr.send();
        });
    }

    async createCms(jwt, hash, certificate) {
        return await new Promise((resolve, reject) => {
            hash = arrayBufferToBase64(hash);
            console.log(hash);
            // const hex = buf2hex(hash);

            const xhr = new XMLHttpRequest();
            xhr.open("POST",  "http://localhost:8002/sign", true);
            xhr.setRequestHeader('Authorization', jwt);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onload = function(){
                let pemCsr = window.atob(JSON.parse(this.responseText).cms);
                resolve(pemCsr);
            }
            // console.log(certificate);
            xhr.send('{"algorithm": "sha256", "cert": "' + window.btoa(certificate) + '", "hash": "' + hash + '", "timestamp": true }');
        });
    }
}
