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

// SNMP Error Status Codes
enum class SnmpErrorStatus : int64_t
{
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5
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

struct SnmpVarBind
{
    std::string oid;
    std::string value; // OctetString response value
};

// Parses a raw SNMPv1/v2c UDP payload. Returns true on valid structure.
bool parseSnmpPacket(const uint8_t *data, size_t len, SnmpMessage &outMsg);
void printPayload(const char *data, ssize_t length);

// Encodes an SNMPv1/v2c GetResponse packet into raw bytes
std::vector<uint8_t> buildSnmpGetResponse(
    const SnmpMessage &request,
    const std::vector<SnmpVarBind> &varBinds,
    SnmpErrorStatus errorStatus = SnmpErrorStatus::NoError,
    int64_t errorIndex = 0);
