import plainAddPlaceholder from '../node-signpdf/helpers/plainAddPlaceholder';
import {findByteRange, removeTrailingNewLine} from "../node-signpdf/helpers";
import SignPdfError from "../node-signpdf/SignPdfError";

export default class PdfService{
    async determineHash(pdfBuffer){
        return await crypto.subtle.digest('SHA-256', (await this.addSignatureOrPlaceholderToPdfBuffer(pdfBuffer)));
    }

    addSignatureToPdf(pdfBuffer, signature){
        signature = signature.replaceAll('\r', '');
        signature = signature.replaceAll('\n', '');
        signature = signature.substr(`-----BEGIN CMS-----`.length);
        signature = signature.substr(0, signature.length - `-----END CMS-----`.length);

        try{
            signature = window.atob(signature);
        } catch(error){
            console.log(error);
            console.log(signature);
        }

        return this.addSignatureOrPlaceholderToPdfBuffer(pdfBuffer, signature);
    }

    async addSignatureOrPlaceholderToPdfBuffer(pdfBuffer, signature = undefined){
        pdfBuffer = plainAddPlaceholder({
            pdfBuffer,
            reason: 'I have reviewed it.',
            signatureLength: 10000,
        });

        let pdf = removeTrailingNewLine(pdfBuffer);

        const {byteRangePlaceholder} = findByteRange(pdf);

        if (!byteRangePlaceholder) {
            throw new SignPdfError(
                `Could not find empty ByteRange placeholder: ${byteRangePlaceholder}`,
                SignPdfError.TYPE_PARSE,
            );
        }
        const byteRangePos = pdf.indexOf(byteRangePlaceholder);
        
        // Calculate the actual ByteRange that needs to replace the placeholder.
        const byteRangeEnd = byteRangePos + byteRangePlaceholder.length;
        const contentsTagPos = pdf.indexOf('/Contents ', byteRangeEnd);
        const placeholderPos = pdf.indexOf('<', contentsTagPos);
        const placeholderEnd = pdf.indexOf('>', placeholderPos);
        const placeholderLengthWithBrackets = (placeholderEnd + 1) - placeholderPos;
        const placeholderLength = placeholderLengthWithBrackets - 2;
        const byteRange = [0, 0, 0, 0];
        byteRange[1] = placeholderPos;
        byteRange[2] = byteRange[1] + placeholderLengthWithBrackets;
        byteRange[3] = pdf.length - byteRange[2];
        let actualByteRange = `/ByteRange [${byteRange.join(' ')}]`;
        actualByteRange += ' '.repeat(byteRangePlaceholder.length - actualByteRange.length);
        
        // Replace the /ByteRange placeholder with the actual ByteRange
        pdf = Buffer.concat([
            pdf.slice(0, byteRangePos),
            Buffer.from(actualByteRange),
            pdf.slice(byteRangeEnd),
        ]);
        pdf = Buffer.concat([
            pdf.slice(0, byteRange[1]),
            pdf.slice(byteRange[2], byteRange[2] + byteRange[3]),
        ]);
        if(signature === undefined) {
            return pdf;
        }
        let hexSignature = Buffer.from(signature, 'binary').toString('hex');
        hexSignature += Buffer
            .from(String.fromCharCode(0).repeat((placeholderLength / 2) - signature.length))
            .toString('hex');
        return Buffer.concat([
            pdf.slice(0, byteRange[1]),
            Buffer.from(`<${hexSignature}>`),
            pdf.slice(byteRange[1]),
        ]);
    }
}