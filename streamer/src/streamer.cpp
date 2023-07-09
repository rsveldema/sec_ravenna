#include <streamer.hpp>
#include <netinet/udp.h>

#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

namespace streamer
{

    std::optional<ServerSocket> IO::create_server_socket(in_port_t port)
    {
        const int af = AF_INET;
        const int fd = socket(af, SOCK_STREAM, 0);
        if (fd < 0)
        {
            fprintf(stderr, "sock_init: %s\n", strerror(errno));
            return std::nullopt;
        }

        int ret = 0;
        if (af == AF_INET6)
        {
            struct sockaddr_in6 addr6 = {
                .sin6_family = af,
                .sin6_port = port,
                .sin6_addr = IN6ADDR_ANY_INIT};

            ret = bind(fd, (struct sockaddr *)&addr6, sizeof(addr6));
        }
        else
        {
            struct sockaddr_in addr = {
                .sin_family = af,
                .sin_port = port,
                .sin_addr = {INADDR_ANY}};

            ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        }

        if (ret)
        {
            fprintf(stderr, "sock_bind: %s\n", strerror(errno));
            close(fd);
            return std::nullopt;
        }

        return ServerSocket(fd);
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

        const auto ret = io_uring_register_buf_ring(&m_ring, &reg, 0);
        if (ret)
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

        if (const auto ret = setup_buffer_pool(); !ret.success())
        {
            io_uring_queue_exit(&m_ring);
            return ret;
        }
        return {0};
    }

    IO::~IO()
    {
        munmap(m_buf_ring, get_total_ring_size());
        io_uring_queue_exit(&m_ring);
    }

}