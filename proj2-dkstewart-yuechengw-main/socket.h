#ifndef SOCKET_H
#define SOCKET_H

/**
 * @brief This structure provides the core functions and data to interface with
 * a network socket.
 */
typedef struct {
    /**
     * @brief An opaque handle to the network socket
     */
    void *handle;

    /**
     * @brief Reads up to `size-1` bytes from the socket into `buffer` and
     * appends a NULL byte to the end of the string.
     * Returns the number of bytes read on success and -1 on failure.
     */
    int (*gets)(void *restrict handle, char *buffer, int size);

    /**
     * @brief Writes the NUL-terminated string `buffer` into the socket.
     * Returns the number of bytes written on success and -1 on failure.
     */
    int (*puts)(void *restrict handle, const char *buffer);

    /**
     * @brief Closes the connection managed by `handle` and
     * frees any associated memory.
     */
    void (*close)(void *handle);

} Network_socket;

/**
 * @brief Initializes an unencrypted network stream socket.
 * Returns 0 on success and -1 on failure.
 */
int init_socket(Network_socket *net, const char *hostname, const char *port);

/**
 * @brief Initializes an encrypted TLS network stream socket.
 * Returns 0 on success and -1 on failure.
 */
int init_tls_socket(Network_socket *net, const char *hostname, const char *port,
                    const char *certificate_path);

#endif