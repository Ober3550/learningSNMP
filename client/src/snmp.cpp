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

    class BerWriter
    {
    public:
        void writeByte(uint8_t b)
        {
            buf_.push_back(b);
        }

        void writeBytes(const uint8_t *data, size_t len)
        {
            // Insert bytes into buffer from start ptr to end ptr
            buf_.insert(buf_.end(), data, data + len);
        }

        void writeBytes(const std::vector<uint8_t> &other)
        {
            // Insert bytes from another vector
            buf_.insert(buf_.end(), other.begin(), other.end());
        }

        // Encodes ASN.1 BER definite length (short form < 128, long form >= 128)
        void writeLength(size_t len)
        {
            if (len < 0b1000'0000)
            {
                writeByte(static_cast<uint8_t>(len));
                return;
            }

            std::vector<uint8_t> lenBytes;
            while (len > 0)
            {
                lenBytes.push_back(static_cast<uint8_t>(len & 0xFF));
                len >>= 8;
            }

            // Reverse order of bytes for reading
            // Write the first byte that specifies how many bytes make up the length
            std::reverse(lenBytes.begin(), lenBytes.end());
            writeByte(static_cast<uint8_t>(0x80 & lenBytes.size()));
            writeBytes(lenBytes);
        }

        // Wraps a pre-encoded payload with a Tag and Length
        void writeTLV(uint8_t tag, const std::vector<uint8_t> &payload)
        {
            writeByte(tag);
            writeLength(payload.size());
            writeBytes(payload);
        }

        void writeTLV(Asn1Tag tag, const std::vector<uint8_t> &payload)
        {
            writeTLV(static_cast<uint8_t>(tag), payload);
        }

        void writeInteger(int64_t value)
        {
            std::vector<uint8_t> bytes;
            uint64_t uval = static_cast<uint64_t>(value);

            // If the integer is negative when we shift right there'll be many leading 1 bits
            // If we populate the top of the value with 1 bits when we shift
            // we can determine if there's no more non-1 bits remaining and encoded a negative integer in less bytes
            const uint64_t signFill = (value < 0) ? (0xFFULL << 56) : 0ULL;

            // Pull the bytes from the value and populate the buffer
            do
            {
                bytes.push_back(static_cast<uint8_t>(uval & 0xFF));
                uval = (uval >> 8) | signFill;
            } while (uval != 0 && uval != static_cast<uint64_t>(-1));

            // bytes is currently stored little-endian (bytes.back() will become the first byte after reverse)
            // If the value is positive (or zero) but the most significant byte has its top bit set
            // that would look negative to the decoder, so we push a 0x00 sign-padding byte
            if (value >= 0 && (bytes.back() & 0x80) != 0)
            {
                bytes.push_back(0x00);
            }
            // If the value is negative and the most significant byte's top bit is 0
            // add a 0xFF sign-padding byte so the top bit on the wire is 1
            else if (value < 0 && (bytes.back() & 0x80) == 0)
            {
                bytes.push_back(0xFF);
            }

            std::reverse(bytes.begin(), bytes.end());
            writeTLV(Asn1Tag::Integer, bytes);
        }

        void writeOctetString(const std::string &str)
        {
            writeByte(static_cast<uint8_t>(Asn1Tag::OctetString));
            writeLength(str.size());
            writeBytes(reinterpret_cast<const uint8_t *>(str.data()), str.size());
        }

        bool writeOid(const std::string &oidStr)
        {
            std::vector<uint64_t> subIds;
            std::istringstream iss(oidStr);
            std::string token;

            // Extract string delimeted by '.'
            while (std::getline(iss, token, '.'))
            {
                if (token.empty())
                    return false;
                // Use standard string to unsigned long long utility
                subIds.push_back(std::stoull(token));
            }
            if (subIds.size() < 2)
            {
                std::cerr << "Sub ids require more than 1 value" << std::endl;
                return false;
            }
        }

    private:
        std::vector<uint8_t> buf_;
    };
}

bool parseSnmpPacket(const uint8_t *data, size_t len, SnmpMessage &outMsg)
{
    BerReader reader(data, len);

    // 1. Outer Message SEQUENCE length
    size_t seqLen = 0;
    if (!reader.expectTag(Asn1Tag::Sequence) || !reader.readLength(seqLen))
    {
        std::cerr << "Failed to read outer message sequence" << std::endl;
        return false;
    }

    // 2. Version and Community String
    if (!reader.readInteger(outMsg.version))
    {
        std::cerr << "Failed to read version" << std::endl;
        return false;
    }
    if (!reader.readOctetString(outMsg.community))
    {
        std::cerr << "Failed to read community string" << std::endl;
        return false;
    }

    // 3. PDU Header type
    size_t pduLen = 0;
    if (!reader.readTag(outMsg.pduType) || !reader.readLength(pduLen))
    {
        std::cerr << "Failed to read pdu header" << std::endl;
        return false;
    }

    // 4. Request ID, Error Status, Error Index
    if (!reader.readInteger(outMsg.requestId))
    {
        std::cerr << "Failed to read request id" << std::endl;
        return false;
    }
    if (!reader.readInteger(outMsg.errorStatus))
    {
        std::cerr << "Failed to read error status" << std::endl;
        return false;
    }
    if (!reader.readInteger(outMsg.errorIndex))
    {
        std::cerr << "Failed to read error index" << std::endl;
        return false;
    }

    // 5. VarBind List SEQUENCE
    size_t varBindListLen = 0;
    if (!reader.expectTag(Asn1Tag::Sequence) || !reader.readLength(varBindListLen))
    {
        std::cerr << "Failed to read var bind length" << std::endl;
        return false;
    }

    // 6. Loop through each VarBind SEQUENCE
    BerReader vbListReader(reader.currentPtr(), varBindListLen);
    while (vbListReader.remaining() > 0)
    {
        size_t vbLen = 0;
        if (!vbListReader.expectTag(Asn1Tag::Sequence) || !vbListReader.readLength(vbLen))
        {
            std::cerr << "Failed to read var bind list" << std::endl;
            return false;
        }

        std::string oid;
        if (!vbListReader.readOid(oid))
        {
            std::cerr << "Failed to read oid" << std::endl;
            return false;
        }
        outMsg.oids.push_back(oid);

        // Read and skip the value TLV (for GetRequest, this is 0x05 0x00 Null)
        uint8_t valTag = 0;
        size_t valLen = 0;

        if (!vbListReader.readTag(valTag) || !vbListReader.readLength(valLen))
        {
            std::cerr << "Failed to read tag and length for skip value" << std::endl;
            return false;
        }
        if (valLen > 0 && !vbListReader.skipValue(valLen))
        {
            // Skip NULL value instead of reading for GetRequest
            std::cerr << "Failed to skip Null message" << std::endl;
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