#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <errno.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif
#include <stdio.h>
#include <string.h>

int main()
{
    printf("Hello from server\n");
    return 0;

    int result = 0;
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    /*** SOCKET ***/
    if (socket_fd < 0) {
        fprintf(stderr, "Error while creating the socket: %s\n", strerror(errno));
        result = 1;
        goto cleanup;
    }

    /*** OPTIONS ***/
    int opt = 1;
    #ifdef _WIN32
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
    #else
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    #endif
        fprintf(stderr, "Error while setting socket options\n");
        result = 1;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(8080);

cleanup:
    return result;
}
