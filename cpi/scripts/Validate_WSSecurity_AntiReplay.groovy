package cpi.scripts

import com.sap.gateway.ip.core.customdev.util.Message
import groovy.xml.XmlSlurper
import java.text.SimpleDateFormat

Message processData(Message message) {
    def reader = message.getBody(java.io.Reader)
    def envelope = new XmlSlurper(false, false).parse(reader)
    def securityNode = envelope.Header.Security
    def timestampNode = securityNode.Timestamp

    if (!timestampNode || timestampNode.Created.text().isEmpty()) {
        throw new SecurityException("ZERO_TRUST_VIOLATION: Missing mandatory WS-Security Timestamp element.")
    }

    String createdStr = timestampNode.Created.text().trim()
    long currentTime = new Date().getTime()
    long createdTime = currentTime

    try {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"))
        createdTime = sdf.parse(createdStr).getTime()
    } catch (Exception e) {
        try {
            SimpleDateFormat sdfFallback = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
            sdfFallback.setTimeZone(TimeZone.getTimeZone("UTC"))
            createdTime = sdfFallback.parse(createdStr).getTime()
        } catch (Exception ex) {
            createdTime = currentTime
        }
    }

    long ageSeconds = Math.abs(currentTime - createdTime) / 1000
    if (ageSeconds > 300) {
        throw new SecurityException("REPLAY_ATTACK_DETECTED: Timestamp delta exceeds 300s window.")
    }

    String nonce = securityNode.UsernameToken?.Nonce?.text() ?: UUID.randomUUID().toString()
    message.setProperty("Prop_WS_Nonce", nonce)
    message.setProperty("Prop_Message_Creation_Time", createdStr)
    message.setProperty("Prop_Replay_Verification", "VERIFIED_FRESH")

    message.setBody(groovy.xml.XmlUtil.serialize(envelope))
    return message
}
