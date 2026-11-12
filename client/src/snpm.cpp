#include "snmp.hpp"
#include <sstream>

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

    private:
        const uint8_t *data_;
        size_t len_;
        size_t pos_;
    };
}