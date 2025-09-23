#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

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
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        fprintf(stderr, "Error while setting socket options: %s\n", strerror(errno));
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
