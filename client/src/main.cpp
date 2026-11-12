#include <iostream>
#include <iomanip>
#include <cctype>
#include <string_view>
#include <array>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "snmp.hpp"

int main()
{
    constexpr uint16_t PORT = 161;
    constexpr size_t BUFFER_SIZE = 4096;

    // 1. Create a UDP socket (IPv4, Datagram)
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        std::perror("Failed to create socket");
        return 1;
    }

    // Optional: Allow immediate port reuse after restarting the app
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 2. Configure the server address structure
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all network interfaces (0.0.0.0)
    server_addr.sin_port = htons(PORT);       // Convert port to network byte order

    // 3. Bind the socket to UDP port 161
    if (bind(sockfd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
    {
        std::perror("Bind failed");
        close(sockfd);
        return 1;
    }

    std::cout << "Listening for UDP packets on port " << PORT << "..." << std::endl;

    // 4. Receive loop
    std::array<char, BUFFER_SIZE> buffer{};
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    while (true)
    {
        ssize_t bytes_received = recvfrom(
            sockfd,
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<sockaddr *>(&client_addr),
            &client_len);

        if (bytes_received < 0)
        {
            std::perror("recvfrom error");
            continue;
        }

        // Convert client IP to readable string
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        std::cout << "Received " << bytes_received << " bytes from "
                  << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;

        // Print Raw Bytes to check end of message
        printPayload(buffer.data(), bytes_received);

        SnmpMessage msg;
        const auto *rawBytes = reinterpret_cast<const uint8_t *>(buffer.data());

        if (parseSnmpPacket(rawBytes, static_cast<size_t>(bytes_received), msg))
        {
            if (msg.pduType == static_cast<uint8_t>(SnmpPduType::GetRequest) && !msg.oids.empty())
            {
                std::vector<SnmpVarBind> replyBinds;

                for (const auto &oid : msg.oids)
                {
                    if (oid == "1.3.6.1.2.1.1.1.0")
                    {
                        replyBinds.push_back({oid, "Custom C++ Clang SNMP Agent"});
                    }
                    else
                    {
                        replyBinds.push_back({oid, "Unknown OID"});
                    }
                }

                std::vector<uint8_t> responseBytes = buildSnmpGetResponse(msg, replyBinds);

                ssize_t sent = sendto(
                    sockfd,
                    responseBytes.data(),
                    responseBytes.size(),
                    0,
                    reinterpret_cast<sockaddr *>(&client_addr),
                    client_len);

                if (sent < 0)
                {
                    std::perror("sendto failed");
                }
                else
                {
                    std::cout << "  Sent " << sent << " byte GetResponse!\n";
                }
            }
        }
        else
        {
            std::cout << "  Packet is not a valid SNMPv1/v2c datagram.\n";
        }

        // Reset client_len before the next recvfrom call
        client_len = sizeof(client_addr);
    }

    close(sockfd);
    return 0;
}
