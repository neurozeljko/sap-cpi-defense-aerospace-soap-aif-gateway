package cpi.scripts

import com.sap.gateway.ip.core.customdev.util.Message
import groovy.json.JsonOutput

Message processData(Message message) {
    def exception = message.getProperty("CamelExceptionCaught")
    String clientCertSubject = message.getProperty("Prop_Client_Cert_Subject") ?: "CN=Lockheed-Martin-Defense-PKI, OU=ITAR-Classified, O=DoD-Approved-Supplier, C=US"
    String correlationId = message.getHeader("SAP_MplCorrelationId", String) ?: UUID.randomUUID().toString()
    String errorReason = exception ? exception.getMessage() : "Cryptographic signature or anti-replay validation failed."

    def aifPayload = [
        aifBusinessMonitoringNotice: [
            interfaceNamespace: "/DEFENSE/SEC",
            interfaceName: "CLASSIFIED_CONTRACT_INB",
            interfaceVersion: "V1_0",
            messageGuid: correlationId,
            businessAlert: [
                alertLevel: "DEFENSE_CRITICAL",
                supplierPKIIdentity: clientCertSubject,
                faultCategory: "WS_SECURITY_INTEGRITY_BREACH",
                fioriNotificationText: "Vojna nabavka blokirana: ${errorReason}. Identitet dobavljača: ${clientCertSubject}",
                recommendedCommandAction: "Provjeriti klijentski X.509 sertifikat dobavljača i provjeriti sinhronizaciju NTP servera."
            ],
            auditMetadata: [
                incidentTimestamp: new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                cpiExecutionNode: "BTP_EU10_CPI_GATEWAY_026"
            ]
        ]
    ]

    message.setBody(JsonOutput.prettyPrint(JsonOutput.toJson(aifPayload)))
    message.setHeader("Content-Type", "application/json")
    message.setHeader("X-AIF-Alert-Level", "CRITICAL")
    return message
}
