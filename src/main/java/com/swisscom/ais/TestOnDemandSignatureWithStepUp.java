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
package com.swisscom.ais;

import com.swisscom.ais.client.impl.AisClientImpl;
import com.swisscom.ais.client.model.PdfHandle;
import com.swisscom.ais.client.model.RevocationInformation;
import com.swisscom.ais.client.model.SignatureResult;
import com.swisscom.ais.client.model.SignatureStandard;
import com.swisscom.ais.client.model.UserData;
import com.swisscom.ais.client.model.VisibleSignatureDefinition;
import com.swisscom.ais.client.rest.RestClientConfiguration;
import com.swisscom.ais.client.rest.RestClientImpl;
import com.swisscom.ais.client.rest.model.DigestAlgorithm;

import java.util.Collections;
import java.util.Properties;

public class TestOnDemandSignatureWithStepUp {

    public static void main(String[] args) throws Exception {
        Properties properties = new Properties();
        properties.load(TestOnDemandSignatureWithStepUp.class.getResourceAsStream("/local-config.properties"));

        RestClientConfiguration config = new RestClientConfiguration();
        config.setFromProperties(properties);

        RestClientImpl restClient = new RestClientImpl();
        restClient.setConfiguration(config);

        try (AisClientImpl aisClient = new AisClientImpl(restClient)) {
            UserData userData = new UserData();
            userData.setFromProperties(properties);
            userData.setConsentUrlCallback((consentUrl, userData1) -> System.out.println("Consent URL: " + consentUrl));
            userData.setAddTimestamp(true);
            userData.setAddRevocationInformation(RevocationInformation.DEFAULT);
            userData.setSignatureStandard(SignatureStandard.PADES_BASELINE);

            PdfHandle document = new PdfHandle();
            document.setInputFromFile(properties.getProperty("local.test.inputFile"));
            document.setOutputToFile(properties.getProperty("local.test.outputFilePrefix") + System.currentTimeMillis() + ".pdf");
            document.setDigestAlgorithm(DigestAlgorithm.SHA512);

            // the image place, size and location are customizable
            // to create a visible signature in the pdf, specify the signature definition and the page. Optionally, provide an icon that will be embedded in the visual signature
            document.setVisibleSignatureDefinition(new VisibleSignatureDefinition(200, 200, 150, 30, 0, properties.getProperty("local.test.visibleSignatureFile"), null));
 
            SignatureResult result = aisClient.signWithOnDemandCertificateAndStepUp(Collections.singletonList(document), userData);
            System.out.println("Final result: " + result);
        }
    }

}
