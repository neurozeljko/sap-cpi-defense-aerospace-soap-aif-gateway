package cpi.scripts

import com.sap.gateway.ip.core.customdev.util.Message
import groovy.xml.XmlSlurper
import groovy.json.JsonOutput

Message processData(Message message) {
    def reader = message.getBody(java.io.Reader)
    def envelope = new XmlSlurper(false, false).parse(reader)
    def bodyContent = envelope.Body.ClassifiedProcurementContract

    if (!bodyContent) {
        throw new IllegalArgumentException("SCHEMA_BREACH: ClassifiedProcurementContract body segment missing.")
    }

    String contractId = bodyContent.ContractId.text() ?: "CTR-MIL-" + UUID.randomUUID().toString().take(8).toUpperCase()
    String natoStockNumber = bodyContent.NATOStockNumber.text() ?: "NSN-1005-01-587-8941"
    String classificationLevel = bodyContent.SecurityClassification.text() ?: "NATO_SECRET"
    String weaponSystemCode = bodyContent.WeaponSystemCategory.text() ?: "AVIONICS_RADAR_ARRAY"
    double contractedSum = bodyContent.ProcurementValueEUR.text() ? bodyContent.ProcurementValueEUR.text().toDouble() : 45000000.00

    def canonicalContract = [
        s4DefenseProcurementHeader: [
            contractReference: contractId,
            procurementType: "DEFENSE_DIRECT_ACQUISITION",
            natoStockNumber: natoStockNumber,
            securityClassification: classificationLevel,
            weaponSystem: weaponSystemCode,
            contractValueEUR: contractedSum,
            antiReplayNonceToken: message.getProperty("Prop_WS_Nonce") ?: "STATIC-NONCE",
            originatingSupplierPKI: message.getProperty("Prop_Client_Cert_Subject") ?: "CN=Lockheed-Martin-Defense-PKI, OU=ITAR-Classified, O=DoD-Approved-Supplier, C=US",
            auditTimestamp: new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'")
        ]
    ]

    message.setBody(JsonOutput.prettyPrint(JsonOutput.toJson(canonicalContract)))
    message.setHeader("Content-Type", "application/json")
    message.setHeader("X-Defense-Classification", classificationLevel)
    return message
}
