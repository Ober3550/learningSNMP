#include "snmp.hpp"
#include <sstream>
#include <iostream>
#include <iomanip>

namespace
{
    class BerReader
    {
    public:
        // Use move semantics to move the data internal to the reader on construction
        BerReader(const uint8_t *data, size_t len) : data_(data), len_(len), pos_(0) {}

        // Check to see if the buffer still has bytes to consume
        bool hasBytes(size_t count) const
        {
            return pos_ + count <= len_;
        }

        // Check what type the next data is
        bool readTag(uint8_t &tag)
        {
            if (!hasBytes(1))
                return false;
            tag = data_[pos_++];
            return true;
        }

        // Read a byte checking whether the next type matches the expected type
        bool expectTag(Asn1Tag expected)
        {
            if (!hasBytes(1))
                return false;
            return data_[pos_++] == static_cast<uint8_t>(expected);
        }

        bool readLength(size_t &length)
        {
            if (!hasBytes(1))
                return false;

            uint8_t first = data_[pos_++];

            // If highest bit is 0
            // length is 0-127
            // return true if buffer contains length bytes
            if ((first & 0b1000'0000) == 0)
            {
                length = first;
                return hasBytes(length);
            }

            // If highest bit is 1 lower bits determine number of bytes length is encoded in
            size_t numBytes = first & 0b0111'1111;
            if (numBytes == 0 || numBytes > sizeof(size_t) || !hasBytes(numBytes))
            {
                return false;
            }

            // Shift and accumulate value for length
            length = 0;
            for (size_t i = 0; i < numBytes; ++i)
            {
                length = (length << 8) | data_[pos_++];
            }

            // Return whether buffer contains atleast as many bytes as length
            return hasBytes(length);
        }

        bool readInteger(int64_t &value)
        {
            size_t len = 0;
            // Check that the type of the next bytes are integer
            // and that the length is between 1 and 8 bytes
            if (!expectTag(Asn1Tag::Integer) || !readLength(len) || len == 0 || len > 8)
            {
                return false;
            }

            // If the top bit is 1 set all bits in value to 1
            value = (data_[pos_] & 0x80) ? -1 : 0;
            for (size_t i = 0; i < len; ++i)
            {
                value = (value << 8) | data_[pos_++];
            }
            return true;
        }

        bool readOctetString(std::string &str)
        {
            size_t len = 0;
            // Check that the type of the next bytes are octet string
            // and the length of the buffer to consume
            if (!expectTag(Asn1Tag::OctetString) || !readLength(len))
            {
                return false;
            }

            // Construct a string from the buffer
            // Cast from uint8_t* bytes to char*
            str.assign(reinterpret_cast<const char *>(&data_[pos_]), len);
            pos_ += len;
            return true;
        }

        bool readOid(std::string &oidStr)
        {
            size_t len = 0;
            // Check that the next bytes are the object identifier
            // and the length of the buffer to consume
            if (!expectTag(Asn1Tag::ObjectIdentifier) || !readLength(len) || len == 0)
            {
                return false;
            }

            // Create a stream buffer to push the data into
            std::ostringstream oss;
            size_t endPos = pos_ + len;
            uint8_t firstByte = data_[pos_++];

            // First byte encodes first two sub-identifieers: (40 * A) + B
            oss << (firstByte / 40) << "." << (firstByte % 40);

            // Remaining sub-identifiers use Base-128 VLQ encoding
            // Variable Length Quantity: If bit 8 is 1 continue, if bit 8 is 0 end of subId
            uint64_t subId = 0;
            while (pos_ < endPos)
            {
                uint8_t b = data_[pos_++];
                subId = (subId << 7) | (b & 0x7F);
                if ((b & 0x80) == 0)
                {
                    // Push current subId to stream and reset for next subId
                    oss << "." << subId;
                    subId = 0;
                }
            }

            oidStr = oss.str();
            return true;
        }

        bool skipValue(size_t len)
        {
            if (!hasBytes(len))
            {
                return false;
            }
            pos_ += len;
            return true;
        }

        size_t remaining() const { return len_ - pos_; }
        const uint8_t *currentPtr() const { return &data_[pos_]; }

    private:
        const uint8_t *data_;
        size_t len_;
        size_t pos_;
    };
}

bool parseSnmpPacket(const uint8_t *data, size_t len, SnmpMessage &outMsg)
{
    BerReader reader(data, len);

    // 1. Outer Message SEQUENCE length
    size_t seqLen = 0;
    if (!reader.expectTag(Asn1Tag::Sequence) || !reader.readLength(seqLen))
    {
        std::cout << "Failed to read outer message sequence" << std::endl;
        return false;
    }

    // 2. Version and Community String
    if (!reader.readInteger(outMsg.version))
    {
        std::cout << "Failed to read version" << std::endl;
        return false;
    }
    if (!reader.readOctetString(outMsg.community))
    {
        std::cout << "Failed to read community string" << std::endl;
        return false;
    }

    // 3. PDU Header type
    size_t pduLen = 0;
    if (!reader.readTag(outMsg.pduType) || !reader.readLength(pduLen))
    {
        std::cout << "Failed to read pdu header" << std::endl;
        return false;
    }

    // 4. Request ID, Error Status, Error Index
    if (!reader.readInteger(outMsg.requestId))
    {
        std::cout << "Failed to read request id" << std::endl;
        return false;
    }
    if (!reader.readInteger(outMsg.errorStatus))
    {
        std::cout << "Failed to read error status" << std::endl;
        return false;
    }
    if (!reader.readInteger(outMsg.errorIndex))
    {
        std::cout << "Failed to read error index" << std::endl;
        return false;
    }

    // 5. VarBind List SEQUENCE
    size_t varBindListLen = 0;
    if (!reader.expectTag(Asn1Tag::Sequence) || !reader.readLength(varBindListLen))
    {
        std::cout << "Failed to read var bind length" << std::endl;
        return false;
    }

    // 6. Loop through each VarBind SEQUENCE
    BerReader vbListReader(reader.currentPtr(), varBindListLen);
    while (vbListReader.remaining() > 0)
    {
        size_t vbLen = 0;
        if (!vbListReader.expectTag(Asn1Tag::Sequence) || !vbListReader.readLength(vbLen))
        {
            std::cout << "Failed to read var bind list" << std::endl;
            return false;
        }

        std::string oid;
        if (!vbListReader.readOid(oid))
        {
            std::cout << "Failed to read oid" << std::endl;
            return false;
        }
        outMsg.oids.push_back(oid);

        // Read and skip the value TLV (for GetRequest, this is 0x05 0x00 Null)
        uint8_t valTag = 0;
        size_t valLen = 0;

        if (!vbListReader.readTag(valTag) || !vbListReader.readLength(valLen))
        {
            std::cout << "Failed to read tag and length for skip value" << std::endl;
            return false;
        }
        if (valLen > 0 && !vbListReader.skipValue(valLen))
        {
            // Skip NULL value instead of reading for GetRequest
            std::cout << "Failed to skip Null message" << std::endl;
            return false;
        }
    }

    return true;
}

// Helper function to print raw bytes as Hex and safe ASCII
void printPayload(const char *data, ssize_t length)
{
    std::cout << "  Hex:   ";
    for (ssize_t i = 0; i < length; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << " ";
    }
    // Reset stream formatting back to decimal
    std::cout << std::dec << "\n  ASCII: ";

    for (ssize_t i = 0; i < length; ++i)
    {
        unsigned char c = static_cast<unsigned char>(data[i]);
        std::cout << (std::isprint(c) ? static_cast<char>(c) : '.');
    }
    std::cout << std::endl;
}