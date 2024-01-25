import AcmeService from "./acme/acmeService"
import PdfService from "./files/PdfService"
import BrowserSideCertificateService from "./certificates/browserSideCertificateService";
import SaasService from "./certificates/SaasService";
import {toBuffer} from "./helpers/bufferHelper"
import FileService from "./files/fileService"

const acmeService = new AcmeService();
const pdfService = new PdfService();

const browserSideCertificateService = new BrowserSideCertificateService();
const saasService = new SaasService();
const fileService = new FileService();
let certificate;

const fetchAcmeCertificate = async function(event){
    let jwt = document.querySelector('#jwt-token').value
    const domain = "900020108"

    if(document.getElementById('service-dropdown').value === "Browser") {
        const csr = await browserSideCertificateService.createCsr(domain);
        const pubKey = await browserSideCertificateService.exportPublicKey()
        document.querySelector('#csr-textarea').value = csr;
        certificate = await acmeService.fetchAcmeCertificate(
            domain,
            csr,
            jwt,
            pubKey);
        document.querySelector('#certificate-textarea')
            .value = certificate;
    } else {
        const csr = await saasService.createCsr(jwt);
        document.querySelector('#csr-textarea').value = csr;
        certificate = await acmeService.fetchAcmeCertificate(
            domain,
            csr,
            jwt);
        document.querySelector('#certificate-textarea')
            .value = certificate;
    }

    enableHandleFiles();
}

const enableHandleFiles = function(){
    const jwt = document.querySelector('#jwt-token').value
    if(document.getElementById('service-dropdown').value === "Browser"){
        document.getElementById('sign-pdf-input').removeAttribute("disabled");
        fileService.handleFiles('sign-pdf-input', (fileArrayBuffer)=>{
            const buffer = toBuffer(fileArrayBuffer);
            pdfService.determineHash(buffer)
                .then(hash => browserSideCertificateService.createCms(hash, certificate))
                .then(cms => {
                    document.querySelector('#cms-textarea')
                        .value = cms;
                    return cms;
                })
                .then(cms => pdfService.addSignatureToPdf(buffer, cms))
                .then(pdf => fileService.storeFile('sign-pdf-output', pdf));
        });
        fileService.handleDownload('sign-pdf-output');
    } else {
        document.getElementById('sign-pdf-input').removeAttribute("disabled");
        fileService.handleFiles('sign-pdf-input', (fileArrayBuffer)=>{
            const buffer = toBuffer(fileArrayBuffer);
            pdfService.determineHash(buffer)
                .then(hash => saasService.createCms(jwt, hash, certificate))
                .then(cms => {
                    document.querySelector('#cms-textarea')
                        .value = cms;
                    return cms;
                })
                .then(cms => pdfService.addSignatureToPdf(buffer, cms))
                .then(pdf => fileService.storeFile('sign-pdf-output', pdf));
        });
        fileService.handleDownload('sign-pdf-output');
    }
}

browserSideCertificateService.initAsync()
    .then(()=>console.log('Finished initialization'));

document.querySelector('#jwt-token').addEventListener('change', () => {
    document.querySelector('#service-dropdown').removeAttribute("disabled");
});
document.querySelector('#service-dropdown').addEventListener('change', fetchAcmeCertificate);