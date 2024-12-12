#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "imap.h"
#include "socket.h"

#define CERTIFICATE_PATH ""
#define IMAP_PORT "143"
#define IMAP_TLS_PORT "993"

#define BUFFER_SIZE 1024

typedef enum {
    EXIT_CLI = 1,
    EXIT_CONNECTION = 2,
    EXIT_SERVER_RESPONSE = 3,
    EXIT_PARSE = 4,
    EXIT_OTHER = 5,
} Exit_codes;

static const char *helpstr = "Usage: %s -u USERNAME -p PASSWORD [-f FOLDER]"
                             " [-n MESSAGE_NUM] [-t] COMMAND SERVERNAME\n";

int main(int argc, char *argv[]) {

    char *username = NULL;
    char *password = NULL;
    char *folder = "INBOX";
    char *message_num = "*";
    bool tls_mode = false;
    char *command = NULL;
    char *server_name = NULL;

    (void)message_num;

    int opt;

    // configure the arguments
    while ((opt = getopt(argc, argv, "u:p:f:n:t")) != -1) {
        switch (opt) {
        case 'u':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'f':
            folder = optarg;
            break;
        case 'n':
            if (!is_valid_seqnum(optarg)) {
                printf("Invalid message number\n");
                exit(EXIT_CLI);
            }
            message_num = optarg;
            break;
        case 't':
            tls_mode = true;
            break;
        default:
            printf(helpstr, argv[0]);
            exit(EXIT_CLI);
        }
    }

    if (optind + 2 < argc) {
        printf("%s: too many arguments\n", argv[0]);
        exit(EXIT_CLI);
    }
    if (optind + 2 > argc) {
        printf("%s: not enough arguments\n", argv[0]);
        exit(EXIT_CLI);
    }

    command = argv[optind];
    server_name = argv[optind + 1];

    if (username == NULL) {
        printf("%s: missing required option -- '-u USERNAME'\n", argv[0]);
        exit(EXIT_CLI);
    }

    if (password == NULL) {
        printf("%s: missing required option -- '-p PASSWORD'\n", argv[0]);
        exit(EXIT_CLI);
    }

    // shoot socket to server

    Network_socket socket;
    if (tls_mode) {
        if (init_tls_socket(&socket, server_name, IMAP_TLS_PORT,
                            CERTIFICATE_PATH)) {
            printf("Failed to connect to server '%s' on port %s\n", server_name,
                   IMAP_TLS_PORT);
            exit(EXIT_CONNECTION);
        }
    } else {
        if (init_socket(&socket, server_name, IMAP_PORT)) {
            printf("Failed to connect to server '%s' on port %s\n", server_name,
                   IMAP_PORT);
            exit(EXIT_CONNECTION);
        }
    }

    IMAP_context *ctx = create_imap_context(&socket);

    char buffer[BUFFER_SIZE]; // a buffer to record message read from socket
    socket.gets(socket.handle, buffer, BUFFER_SIZE);

    // login
    IMAP_ERRC errc;
    if ((errc = login(ctx, username, password))) {
        printf("%s\n", imap_strerr(errc));
        exit(EXIT_SERVER_RESPONSE);
    }

    // choose folder
    if ((errc = select_folder(ctx, folder))) {
        printf("%s\n", imap_strerr(errc));
        exit(EXIT_SERVER_RESPONSE);
    }

    // do task according to command
    if (!strcmp(command, "retrieve")) {
        if ((errc = retrieve(ctx, message_num))) {
            printf("%s\n", imap_strerr(errc));
            exit(EXIT_SERVER_RESPONSE);
        }
    } else if (!strcmp(command, "parse")) {
        if ((errc = parse(ctx, message_num))) {
            printf("%s\n", imap_strerr(errc));
            exit(EXIT_SERVER_RESPONSE);
        }
    } else if (!strcmp(command, "mime")) {
        if ((errc = mime(ctx, message_num))) {
            printf("%s\n", imap_strerr(errc));
            if (errc == IMAP_MIME_ERROR) {
                exit(EXIT_PARSE);
            }
            exit(EXIT_SERVER_RESPONSE);
        }
    } else if (!strcmp(command, "list")) {
        if ((errc = list(ctx))) {
            printf("%s\n", imap_strerr(errc));
            if (errc == IMAP_MIME_ERROR) {
                exit(EXIT_PARSE);
            }
            exit(EXIT_SERVER_RESPONSE);
        }
    } else {
        fprintf(stderr, "Please provide correct command! "
                        "<'retrieve', 'parse', 'mime', 'list'>\n");
        exit(EXIT_CLI);
    }

    free_imap_context(ctx);
    socket.close(socket.handle);
    return 0;
}
