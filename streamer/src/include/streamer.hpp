#pragma once

#include "Timeout.hpp"
#include <optional>
#include <array>
#include <variant>
#include <string>
#include <vector>
#include <memory>
#include <assert.h>
#include <liburing.h>
#include <arpa/inet.h>

namespace streamer
{
    class PacketPayload
    {
    private:
        std::array<uint8_t, 1500> m_data;
    };

    class ServerAddress
    {
        std::string m_addr;
    };

    class Packet
    {
    public:
        ServerAddress m_from;
        PacketPayload *m_payload;
    };

    class PacketPool
    {
    public:
        PacketPool(size_t size)
        {
            for (size_t i = 0; i < size; i++)
            {
                free(std::make_unique<Packet>());
            }
        }

    private:
        std::unique_ptr<Packet> alloc()
        {
            assert(m_pkts.size());

            auto ret = std::move(m_pkts.back());
            m_pkts.pop_back();
            return ret;
        }

        void free(std::unique_ptr<Packet> pkt)
        {
            m_pkts.emplace_back(std::move(pkt));
        }

    private:
        std::vector<std::unique_ptr<Packet>> m_pkts;
    };

    class ClientSocket
    {
        void connect(const ServerAddress &address);
    };

    class ClientConnection
    {
        void send(const std::unique_ptr<Packet> &pkt);
        std::optional<std::unique_ptr<Packet>> recv();
    };

    class ServerSocket
    {
    public:
        ServerSocket(int fd) : m_fd(fd) {}

        std::optional<ClientConnection> listen(const Timeout &timeout);

    private:
        int m_fd;
    };

    class Result
    {
    public:
        Result(int ret) : m_ret(ret) {}
        int code() const { return m_ret; }
        bool success() const { return m_ret == 0; }

        static Result ok() { return SUCCESS_CODE; }

        constexpr static int SUCCESS_CODE = 0;
    private:
        int m_ret;
    };



    class IO
    {
    public:
        Result init();

        std::optional<ServerSocket> create_server_socket(in_port_t port);
        void multicast(const ServerAddress &addr, Packet &pkt);


        ~IO();
    private:
        io_uring m_ring;
        io_uring_buf_ring *m_buf_ring = nullptr;
        unsigned char *m_buffer_base = nullptr;

        constexpr static size_t BUF_SHIFT = 12; /* 4k */

        constexpr static size_t QUEUE_DEPTH = 64;

        constexpr static size_t CQES = (QUEUE_DEPTH * 16);
        constexpr static size_t NUM_BUFFERS = CQES;

        Result setup_buffer_pool();

        consteval static size_t buffer_size()
        {
            return 1U << BUF_SHIFT;
        }

        unsigned char *get_buffer(unsigned idx)
        {
            assert(idx < NUM_BUFFERS);
            return m_buffer_base + (idx << BUF_SHIFT);
        }

        /** size of the uring buffer headers
         * and the buffer area size
        */
        consteval static size_t get_total_ring_size() {
            return
            (sizeof(io_uring_buf) * NUM_BUFFERS) +
            (buffer_size() * NUM_BUFFERS);
        }
    };
}