#ifndef IMAP_H
#define IMAP_H

#include <stdbool.h>

#include "socket.h"

#define TAG_LENGTH 5

// IMAP Errors
typedef enum {
    IMAP_SUCCESS = 0,
    IMAP_CONNECTION_ERROR,
    IMAP_LOGIN_FAILURE,
    IMAP_MESSAGE_NOT_FOUND,
    IMAP_FOLDER_NOT_FOUND,
    IMAP_RETRIEVE_FAILURE,
    IMAP_MIME_ERROR,
} IMAP_ERRC;

/**
 * @brief Stores information about a connection to an IMAP server
 */
typedef struct {
    Network_socket *socket;
    // reusable buffer for formatting messages to before sending them to the
    // server
    char *restrict outbuf;
    int outbuf_sz;
} IMAP_context;

/**
 * @brief checks if str is a valid IMAP seq-number as specified in
 * https://datatracker.ietf.org/doc/html/rfc3501#autoid-95
 */
bool is_valid_seqnum(const char *str);

/**
 * @brief Converts `errc` into a human readable error message.
 */
const char *imap_strerr(IMAP_ERRC errc);

/**
 * @brief creates an IMAP context
 */
IMAP_context *create_imap_context(Network_socket *socket);

/**
 * @brief frees all memory associated with an IMAP context
 */
void free_imap_context(IMAP_context *ctx);

/**
 * @brief Attempt to login to the IMAP server on the other end of `sockfd`.
 * Returns `IMAP_CONNECTION_ERROR` or `IMAP_LOGIN_FAILURE` on failure.
 */
IMAP_ERRC login(IMAP_context *restrict ctx, const char *username,
                const char *password);

/**
 * @brief Selects the IMAP mailbox to read messages from.
 * Returns `IMAP_CONNECTION_ERROR` or `IMAP_FOLDER_NOT_FOUND` on failure.
 */
IMAP_ERRC select_folder(IMAP_context *restrict ctx, const char *folder);

/**
 * @brief Retrive message from select squence number and print raw message.
 * Returns `IMAP_CONNECTION_ERROR` or `IMAP_FOLDER_NOT_FOUND` on failure.
 */
IMAP_ERRC retrieve(IMAP_context *restrict ctx, const char *messageNum);

/**
 * @brief Retrive message from select squence number and print it's header.
 * From, To, Date, Subject.
 * Returns `IMAP_CONNECTION_ERROR` or `IMAP_RETRIEVE_FAILURE` on failure.
 */
IMAP_ERRC parse(IMAP_context *restrict ctx, const char *messageNum);

/**
 * @brief Retrive message from select squence number and print it's MIME.
 * Multimedia Internet Mail Extension (MIME) messages.
 * Returns `IMAP_CONNECTION_ERROR` or `IMAP_RETRIEVE_FAILURE` on failure.
 */
IMAP_ERRC mime(IMAP_context *restrict ctx, const char *messageNum);

/**
 * @brief Lists the subject lines of all messages in the current folder.
 */
IMAP_ERRC list(IMAP_context *ctx);

#endif