#include <streamer.hpp>
#include <netinet/udp.h>

#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

namespace streamer
{
    constexpr uint64_t FLAG_IS_ACCEPT = 0xdead;

    Result IO::submit_accept(ServerSocketDescriptor &descriptor)
    {
        if (auto *sqe = io_uring_get_sqe(&m_ring))
        {
            printf("submit fd %d\n", descriptor.m_fd);
            io_uring_prep_multishot_accept(sqe, descriptor.m_fd,
                                           (sockaddr *)&descriptor.m_addr, &descriptor.m_addr_len, 0);
            io_uring_sqe_set_data64(sqe, FLAG_IS_ACCEPT);

            const auto ret = io_uring_submit(&m_ring);
            if (ret < 0)
            {
                printf("failed to submit sqe\n");
                return -ret;
            }
            printf("submit %d entries to submit-queue\n", ret);
            return Result::ok();
        }
        else
        {
            printf("failed to get submit-queue-entry\n");
        }

        return -1;
    }

    Result ServerSocket::listen(const Timeout &timeout)
    {
        printf("submit accept\n");
        // queue_accept_conn(ring, recv_s0, args);
        if (const auto ret = m_io.submit_accept(m_descr); !ret.success())
        {
            printf("failed to submit accept\n");
            return ret;
        }

        return Result::ok();
    }

    std::optional<ServerSocket> IO::create_server_socket(in_port_t port)
    {
        const int af = AF_INET;
        const int fd = socket(af, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (fd < 0)
        {
            fprintf(stderr, "sock_init: %s\n", strerror(errno));
            return std::nullopt;
        }
        printf("allocated fd %d for server socket\n", fd);

        {
            int32_t val = 1;
            int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
            assert(ret != -1);
        }

        {
            int32_t val = 1;
            int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
            assert(ret != -1);
        }

        {
            int ret = 0;
            if (af == AF_INET6)
            {
                sockaddr_in6 addr6 = {
                    .sin6_family = af,
                    .sin6_port = htons(port),
                    .sin6_addr = IN6ADDR_ANY_INIT};

                ret = bind(fd, (struct sockaddr *)&addr6, sizeof(addr6));
            }
            else
            {
                sockaddr_in addr {
                    .sin_family = af,
                    .sin_port = htons(port),
                    .sin_addr = {INADDR_ANY}};

                ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
            }

            if (ret)
            {
                fprintf(stderr, "sock_bind: %s\n", strerror(errno));
                close(fd);
                return std::nullopt;
            }
        }

        if (int ret = listen(fd, 128); ret != 0)
        {
            fprintf(stderr, "sock_listen failed: %s\n", strerror(errno));
            close(fd);
            return std::nullopt;
        }

        return ServerSocket(*this, fd);
    }

    /**
     * @brief allocate buffers
     *
     * Memory layout:
     *          N * io_uring_buffer_header
     *          N * buffersize
     *
     * @return Result
     */
    Result IO::setup_buffer_pool()
    {
        void *mapped = mmap(NULL, get_total_ring_size(), PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
        if (mapped == MAP_FAILED)
        {
            fprintf(stderr, "buf_ring mmap: %s\n", strerror(errno));
            return -1;
        }
        m_buf_ring = (struct io_uring_buf_ring *)mapped;

        io_uring_buf_ring_init(m_buf_ring);

        io_uring_buf_reg reg{
            .ring_addr = (unsigned long)m_buf_ring,
            .ring_entries = NUM_BUFFERS,
            .bgid = 0};
        m_buffer_base = (unsigned char *)m_buf_ring +
                        (sizeof(io_uring_buf) * NUM_BUFFERS);

        if (const auto ret = io_uring_register_buf_ring(&m_ring, &reg, 0); ret != 0)
        {
            fprintf(stderr, "buf_ring init failed: %s\n"
                            "NB This requires a kernel version >= 6.0\n",
                    strerror(-ret));
            return ret;
        }

        for (int i = 0; i < NUM_BUFFERS; i++)
        {
            io_uring_buf_ring_add(m_buf_ring,
                                  get_buffer(i),
                                  buffer_size(),
                                  i,
                                  io_uring_buf_ring_mask(NUM_BUFFERS),
                                  i);
        }
        io_uring_buf_ring_advance(m_buf_ring, NUM_BUFFERS);

        return Result::ok();
    }

    Result IO::init()
    {
        if (1)
        {
            unsigned int flags = 0;
            if (int ret = io_uring_queue_init(QUEUE_DEPTH, &m_ring,
                                              flags);
                ret < 0)
            {
                fprintf(stderr, "queue_init failed: %s\n"
                                "NB: This requires a kernel version >= 6.0\n",
                        strerror(-ret));
                return ret;
            }
        }
        else
        {
            io_uring_params params;
            memset(&params, 0, sizeof(params));
            params.cq_entries = QUEUE_DEPTH * 8;
            params.flags = IORING_SETUP_SUBMIT_ALL |
                           IORING_SETUP_COOP_TASKRUN |
                           IORING_SETUP_CQSIZE;

            if (int ret = io_uring_queue_init_params(QUEUE_DEPTH, &m_ring, &params); ret < 0)
            {
                fprintf(stderr, "queue_init failed: %s\n"
                                "NB: This requires a kernel version >= 6.0\n",
                        strerror(-ret));
                return ret;
            }
        }

        if (const auto ret = setup_buffer_pool(); !ret.success())
        {
            io_uring_queue_exit(&m_ring);
            return ret;
        }
        m_init = true;
        return Result::ok();
    }

    IO::~IO()
    {
        munmap(m_buf_ring, get_total_ring_size());
        io_uring_queue_exit(&m_ring);
    }

    void IO::event_loop()
    {
        assert(m_init);
        while (1)
        {
            struct io_uring_cqe *pcqe = nullptr;

            if (int ret = io_uring_wait_cqe(&m_ring, &pcqe); ret == 0)
            {
                printf("got cqe\n");
                const auto cqe = *pcqe;
                io_uring_cqe_seen(&m_ring, pcqe);

                if (1)
                {
                    const auto new_socket = cqe.res;

                    ClientConnection cc(*this, new_socket);
                    m_cb.handle_new_connection(cc);
                }
            }
            else
            {
                // failed to retrieve event from completion-queue
                printf("failed to get cqe\n");
            }
        }
    }
}