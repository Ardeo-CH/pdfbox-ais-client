/*
 * Copyright 2021 Swisscom Trust Services (Schweiz) AG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.swisscom.ais.client.impl;

import com.swisscom.ais.client.AisClientException;
import com.swisscom.ais.client.model.UserData;
import com.swisscom.ais.client.model.VisibleSignatureDefinition;
import com.swisscom.ais.client.rest.model.DigestAlgorithm;
import com.swisscom.ais.client.rest.model.SignatureType;
import com.swisscom.ais.client.utils.Trace;
import com.swisscom.ais.client.utils.Utils;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDTrueTypeFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.encoding.Encoding;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSeedValue;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSeedValueMDP;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static com.swisscom.ais.client.utils.Utils.closeResource;

public class PdfDocument implements Closeable {

    private final InputStream contentIn;
    private final OutputStream contentOut;
    private final VisibleSignatureDefinition signatureDefinition;
    private final ByteArrayOutputStream inMemoryStream;
    private final String name;
    private final Trace trace;

    private String id;
    private PDDocument pdDocument;
    private ExternalSigningSupport pbSigningSupport;
    private String base64HashToSign;
    private DigestAlgorithm digestAlgorithm;

    // ----------------------------------------------------------------------------------------------------

    public PdfDocument(String name, InputStream contentIn, OutputStream contentOut, VisibleSignatureDefinition signatureDefinition, Trace trace) {
        this.name = name;
        this.contentIn = contentIn;
        this.contentOut = contentOut;
        this.signatureDefinition = signatureDefinition;

        this.inMemoryStream = new ByteArrayOutputStream();
        this.trace = trace;
    }

    public void prepareForSigning(DigestAlgorithm digestAlgorithm,
                                  SignatureType signatureType,
                                  UserData userData) throws IOException, NoSuchAlgorithmException {
        this.digestAlgorithm = digestAlgorithm;
        id = Utils.generateDocumentId();
        pdDocument = PDDocument.load(contentIn);

        int accessPermissions = getDocumentPermissions();
        if (accessPermissions == 1) {
            throw new AisClientException("Cannot sign document [" + name + "]. Document contains a certification " +
                    "that does not allow any changes.");
        }

        PDSignature pdSignature = new PDSignature();
        Calendar signDate = Calendar.getInstance();

        if (signatureType == SignatureType.TIMESTAMP) {
            // Now, according to ETSI TS 102 778-4, annex A.2, the type of a Dictionary that holds document timestamp should be DocTimeStamp
            // However, adding this (as of Feb/17/2021), it trips the ETSI Conformance Checked online tool, making it say
            // "There is no signature dictionary in the document". So, for now (Feb/17/2021) this has been removed. This makes the
            // ETSI Conformance Checker happy.
            // pdSignature.setType(COSName.DOC_TIME_STAMP);
            pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            pdSignature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
        } else {
            pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            pdSignature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            // Add 3 Minutes to move signing time within the OnDemand Certificate Validity
            // This is only relevant in case the signature does not include a timestamp
            // See section 5.8.5.1 of the Reference Guide
            signDate.add(Calendar.MINUTE, 3);
        }

        pdSignature.setSignDate(signDate);
        pdSignature.setName(userData.getSignatureName());
        pdSignature.setReason(userData.getSignatureReason());
        pdSignature.setLocation(userData.getSignatureLocation());
        pdSignature.setContactInfo(userData.getSignatureContactInfo());

        SignatureOptions options = new SignatureOptions();
        options.setPreferredSignatureSize(signatureType.getEstimatedSignatureSizeInBytes());

        // create a visible signature at the specified coordinates
        if (signatureDefinition != null) {
            options.setVisualSignature(createVisualSignatureTemplate(pdDocument, signatureDefinition));
            options.setPage(signatureDefinition.getPage());
        }

        pdDocument.addSignature(pdSignature, options);
        // Set this signature's access permissions level to 0, to ensure we just sign the PDF, not certify it
        // for more details: https://wwwimages2.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf see section 12.7.4.5
        setPermissionsForSignatureOnly();

        pbSigningSupport = pdDocument.saveIncrementalForExternalSigning(inMemoryStream);

        MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.getDigestAlgorithm());
        byte[] contentToSign = IOUtils.toByteArray(pbSigningSupport.getContent());
        byte[] hashToSign = digest.digest(contentToSign);
        options.close();
        base64HashToSign = Base64.getEncoder().encodeToString(hashToSign);
    }

    public void finishSignature(byte[] signatureContent, List<byte[]> crlEntries, List<byte[]> ocspEntries) {
        try {
            pbSigningSupport.setSignature(signatureContent);
            closeResource(pdDocument, trace);
            closeResource(contentIn, trace);
            closeResource(inMemoryStream, trace);

            byte[] documentBytes = inMemoryStream.toByteArray();

            if (crlEntries != null || ocspEntries != null) {
                pdDocument = PDDocument.load(documentBytes);

                CrlOcspExtender metadata = new CrlOcspExtender(pdDocument, documentBytes, trace);
                metadata.extendPdfWithCrlAndOcsp(crlEntries, ocspEntries);

                pdDocument.saveIncremental(contentOut);
                closeResource(pdDocument, trace);
            } else {
                contentOut.write(inMemoryStream.toByteArray());
            }
            closeResource(contentOut, trace);
        } catch (Exception e) {
            throw new AisClientException("Failed to embed the signature(s) in the document(s) and close the streams - " + trace.getId(), e);
        }
    }

    @Override
    public void close() {
        closeResource(pdDocument, trace);
        closeResource(contentIn, trace);
        closeResource(inMemoryStream, trace);
        closeResource(contentOut, trace);
    }

    // ----------------------------------------------------------------------------------------------------

    /**
     * Get the permissions for this document from the DocMDP transform parameters dictionary.
     *
     * @return the permission integer value. 0 means no DocMDP transform parameters dictionary exists. Other
     * returned values are 1, 2 or 3. 2 is also returned if the DocMDP dictionary is found but did not
     * contain a /P entry, or if the value is outside the valid range.
     */
    private int getDocumentPermissions() {
        COSBase base = pdDocument.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary) {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary) {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject("Reference");
                if (base instanceof COSArray) {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i) {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary) {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod"))) {
                                base = sigRefDict.getDictionaryObject("TransformParams");
                                if (base instanceof COSDictionary) {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3) {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    private void setPermissionsForSignatureOnly() throws IOException {
        List<PDSignatureField> signatureFields = pdDocument.getSignatureFields();
        PDSignatureField pdSignatureField = signatureFields.get(signatureFields.size() - 1);

        PDSeedValue pdSeedValue = pdSignatureField.getSeedValue();
        if (pdSeedValue == null) {
            COSDictionary newSeedValueDict = new COSDictionary();
            newSeedValueDict.setNeedToBeUpdated(true);
            pdSeedValue = new PDSeedValue(newSeedValueDict);
            pdSignatureField.setSeedValue(pdSeedValue);
        }

        PDSeedValueMDP pdSeedValueMDP = pdSeedValue.getMDP();
        if (pdSeedValueMDP == null) {
            COSDictionary newMDPDict = new COSDictionary();
            newMDPDict.setNeedToBeUpdated(true);
            pdSeedValueMDP = new PDSeedValueMDP(newMDPDict);
            pdSeedValue.setMPD(pdSeedValueMDP);
        }

        pdSeedValueMDP.setP(0); // identify this signature as an author signature, not document certification
    }

    // ----------------------------------------------------------------------------------------------------

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getBase64HashToSign() {
        return base64HashToSign;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    // ----------------------------------------------------------------------------------------------------

    // create a template PDF document with empty signature and return it as a stream.
    private InputStream createVisualSignatureTemplate(PDDocument srcDoc, VisibleSignatureDefinition signatureDefinition) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            if (signatureDefinition.getPage() < 0) {
                // fall back to last page if there is a negative page number
                signatureDefinition.setPage(srcDoc.getNumberOfPages() - 1);
            }

            PDPage page = new PDPage(srcDoc.getPage(signatureDefinition.getPage()).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            var meta = signatureDefinition.getMeta();
            var lineHeight = 10;

            if (signatureDefinition.getX() < 0) {
                // fall back to "sane" defaults if no X position is given
                var pageHalf = (int) (page.getCropBox().getWidth() / 2);
                var baseX = meta.getOrDefault("signatureRole", "").equals("admin")
                        ? pageHalf - signatureDefinition.getWidth() - 30
                        : pageHalf + 30;
                signatureDefinition.setX(baseX);
            }

            if (signatureDefinition.getY() < 0) {
                // fall back to "sane" defaults if no Y position is given
                var baseY = lineHeight * 8; // remember: pdf Y starts at the bottom :)
                signatureDefinition.setY(baseY);
            }

            var rect = new PDRectangle();
            rect.setLowerLeftX(signatureDefinition.getX());
            rect.setUpperRightX(signatureDefinition.getX() + signatureDefinition.getWidth());
            rect.setLowerLeftY(signatureDefinition.getY());
            rect.setUpperRightY(signatureDefinition.getY() + signatureDefinition.getHeight());

            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            switch (srcDoc.getPage(signatureDefinition.getPage()).getRotation()) {
                case 90 -> form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                case 180 -> form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
                case 270 -> form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
            }
            form.setBBox(bbox);

            // from PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            // MODIFICATIONS BY ARDEO GBMH
            try (PDPageContentStream contentStream = new PDPageContentStream(doc, appearanceStream)) {
                // load font & add pdf text (bottom to top)
                contentStream.beginText();
                contentStream.setFont(PDType1Font.HELVETICA, 7); // on the first call per app instance, this will take some time

                contentStream.newLineAtOffset(22, 3); // lift the 1st line a bit, otherwise it will not fit into the rectangle
                contentStream.showText("Signiert auf QuickPool");
                contentStream.newLineAtOffset(0, lineHeight);
                contentStream.showText("Qualifizierte elektronische Signatur - Schweizer Recht");

                contentStream.newLineAtOffset(-22, lineHeight + 4);
                contentStream.showText(meta.getOrDefault("additionalText", ""));
                contentStream.newLineAtOffset(0, lineHeight);
                contentStream.showText(
                        // if location is set, print the location
                        meta.getOrDefault("signatureLocation", "")
                                + (
                                // otherwise just print the date or the fallback (empty string)
                                // if location and date is set, add the ", " string and print date
                                meta.containsKey("signatureLocation") && meta.containsKey("signatureDate")
                                        ? ", " + meta.get("signatureDate")
                                        : meta.getOrDefault("signatureDate", "")));
                contentStream.newLineAtOffset(0, lineHeight);

                contentStream.setFont(loadFont(doc), 13); // use a custom font for the person name
                contentStream.showText(meta.getOrDefault("personName", ""));

                contentStream.endText();

                // embed the image
                ClassLoader ctx = Thread.currentThread().getContextClassLoader();
                try (InputStream qesStream = ctx.getResourceAsStream("qes.png")) {
                    if (qesStream == null) {
                        throw new IOException("Input stream for qes.png was null (looks like the file is missing)");
                    }
                    PDImageXObject image = PDImageXObject.createFromByteArray(doc, qesStream.readAllBytes(), "image/png");
                    contentStream.drawImage(image, 0, 0, 20, 20);
                }
            }
            // END OF    MODIFICATIONS BY ARDEO GBMH

            // no need to set annotations and /P entry
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);

            return new ByteArrayInputStream(baos.toByteArray());
        }
    }

    private static PDFont loadFont(PDDocument doc) throws IOException {
        var ctx = Thread.currentThread().getContextClassLoader();
        try (var stream = ctx.getResourceAsStream("Ephesis-Regular.ttf")) {
            if (stream == null) {
                throw new IOException("Input stream for Ephesis-Regular.ttf was null (looks like the file is missing)");
            }

            return PDTrueTypeFont.load(doc, stream, Encoding.getInstance(COSName.WIN_ANSI_ENCODING));
        }
    }

}
