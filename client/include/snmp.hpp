#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// Standard ASN.1 BER Universal Tags
enum class Asn1Tag : uint8_t
{
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Sequence = 0x30
};

// SNMP Context-Specific PDU Tags
enum class SnmpPduType : uint8_t
{
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    GetResponse = 0xA2,
    SetRequest = 0xA3,
    Trap = 0xA4
};

struct SnmpMessage
{
    int64_t version = -1;
    std::string community;
    uint8_t pduType = 0;
    int64_t requestId = 0;
    int64_t errorStatus = 0;
    int64_t errorIndex = 0;
    std::vector<std::string> oids;
};

// Parses a raw SNMPv1/v2c UDP payload. Returns true on valid structure.
bool parseSnmpPacket(const uint8_t *data, size_t len, SnmpMessage &outMsg);
void printPayload(const char *data, ssize_t length);
