#pragma once

#include "Timeout.hpp"
#include <optional>
#include <variant>
#include <string>

#include <liburing.h>

namespace streamer
{

    class Packet
    {
    };

    class ServerAddress
    {
        std::string m_addr;
    };

    class ClientSocket
    {
        void connect(const ServerAddress& address);
    };

    class ClientConnection
    {
        void send(const Packet& pkt);
        std::optional<Packet> recv();
    };

    class ServerSocket
    {
    public:
        std::optional<ClientConnection> listen(const Timeout &timeout);
    };

    class IO
    {
    public:
        ServerSocket create(int port);
        void multicast(const ServerAddress& addr, Packet &pkt);
    };

    void start_ravenna();

}