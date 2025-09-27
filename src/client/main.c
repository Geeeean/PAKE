#include "network.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    int result = 0;
    int socket_fd = get_socket();

    /*** SOCKET ***/
    if (socket_fd < 0) {
        fprintf(stderr, "Error while creating the socket: %s\n", strerror(errno));
        result = 1;
        goto cleanup;
    }

    /*** ADDRESS ***/
    struct sockaddr_in address = get_address();

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Connection Failed");
        return 1;
    }

    char *msg = "Hello from client!";
    send(socket_fd, msg, strlen(msg), 0);

    char buffer[1024] = {0};
    read(socket_fd, buffer, sizeof(buffer) - 1);
    printf("msg from server: %s\n", buffer);

cleanup:
    close(socket_fd);
    return result;
}
