export default class FileService{
    storedFiles = {};

    handleFiles(elementId, callbackFn){
        const fileElement = document.getElementById(elementId);
        fileElement.addEventListener("change", (bla)=>{
            Array.from(fileElement.files).forEach((file) =>{
                const fr = new FileReader();
                fr.onload = async function(evt) {
                    callbackFn(evt.target.result);
                }
                fr.readAsArrayBuffer(file);
            });
        }, false);
    }

    storeFile(elementId, file){
        if(this.storedFiles[elementId] === undefined){
            this.storedFiles[elementId] = [];
        }
        this.storedFiles[elementId].push(file);
    }

    handleDownload(elementId){
        const downloadElement = document.getElementById(elementId);
        downloadElement.addEventListener("click", (event) => {
            if(this.storedFiles[elementId] !== undefined) {
                this.storedFiles[elementId].forEach((byteArray, index) => {
                    const blob = new Blob([byteArray], {type: "application/pdf"});
                    const link = document.createElement('a');
                    link.href = window.URL.createObjectURL(blob);
                    link.download = elementId + (index === 0 ? '' : '-' + index);
                    link.click();
                });
            }
        });
    }
}