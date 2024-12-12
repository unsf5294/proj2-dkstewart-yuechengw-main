#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket.h"

static int network_gets(void *restrict handle, char *buffer, int size) {
    int bytes_read = read(*(int *)handle, buffer, size - 1);
    if (bytes_read < 0) {
        buffer[0] = '\0';
        return -1;
    }
    buffer[bytes_read] = '\0';
    return bytes_read;
}

static int network_puts(void *restrict handle, const char *buffer) {
    return write(*(int *)handle, buffer, strlen(buffer));
}

static void network_close(void *handle) {
    close(*(int *)handle);
    free(handle);
}

int init_socket(Network_socket *net, const char *hostname, const char *port) {
    struct addrinfo hints = (struct addrinfo){
        .ai_family = AF_UNSPEC, /* IPv4 or IPv6 */
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *servinfo;
    if (getaddrinfo(hostname, port, &hints, &servinfo)) {
        return -1;
    }

    int sockfd = -1;

    /* Try ipv6 */
    for (struct addrinfo *rp = servinfo; sockfd == -1 && rp; rp = rp->ai_next) {
        if (rp->ai_family != AF_INET6)
            continue;

        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
            close(sockfd);
            sockfd = -1;
        }
    }

    /* Fallback to ipv4 */
    for (struct addrinfo *rp = servinfo; sockfd == -1 && rp; rp = rp->ai_next) {
        if (rp->ai_family != AF_INET)
            continue;

        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(servinfo);

    if (sockfd == -1) {
        return -1;
    }

    int *netsock = malloc(sizeof(int));
    *netsock = sockfd;
    *net = (Network_socket){
        .handle = netsock,
        .gets = network_gets,
        .puts = network_puts,
        .close = network_close,
    };
    return 0;
}