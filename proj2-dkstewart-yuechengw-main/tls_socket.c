#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "socket.h"

static int network_tls_gets(void *restrict handle, char *buffer, int size) {
    (void)handle;
    (void)buffer;
    (void)size;
    return -1;
}

static int network_tls_puts(void *restrict handle, const char *buffer) {
    (void)handle;
    (void)buffer;
    return -1;
}

static void network_tls_close(void *handle) {
    (void)handle;
}

int init_tls_socket(Network_socket *net, const char *hostname, const char *port,
                    const char *certificate_path) {
    (void)net;
    (void)hostname;
    (void)port;
    (void)certificate_path;
    *net = (Network_socket){
        .handle = NULL,
        .gets = network_tls_gets,
        .puts = network_tls_puts,
        .close = network_tls_close,
    };
    return -1;
}