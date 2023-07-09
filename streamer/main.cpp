#include <streamer.hpp>
#include <Timeout.hpp>
#include <chrono>

using namespace std::chrono_literals;

class MyCallback : public streamer::CallbackHandler
{
  public:
    void handle_new_connection(streamer::ClientConnection &c)
    {
        printf("got new client connection\n");
        m_conn.push_back(c);
    }

    std::vector<streamer::ClientConnection> m_conn;
};

int main(int argc, char** argv)
{
    printf("BOOTUP\n");
    MyCallback cb;
    streamer::IO io(cb);

    if (const auto ret = io.init(); ! ret.success())
    {
        printf("faile to init IO lib\n");
        return 1;
    }

    if (auto server_socket = io.create_server_socket(12345))
    {
        if (auto ret = server_socket->listen(Timeout(100s)); ! ret.success())
        {
            printf("failed to listen\n");
            return 1;
        }
    } else {
        printf("failed to create server socket\n");
        return 1;
    }


    io.event_loop();

    return 0;
}