#include <ctype.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "imap.h"
#include "socket.h"

#define BUFFER_SIZE 1024
#define INITIAL_WRITE_BUFFER_SIZE 1024

/**
 * @brief Constructs a POSIX regex pattern that matches the
 * IMAP header field `field` and puts the value into
 * matches[1].
 */
#define RMATCH_HEADER_FIELD(field) "^" field ": \\(.*\\)\r\n$"

#define SWAP(x, y)                                                             \
    do {                                                                       \
        typeof(x) tmp = (x);                                                   \
        (x) = (y);                                                             \
        (y) = (tmp);                                                           \
    } while (0)

/**
 * @brief Checks if the string `str` starts with `prefix`.
 */
static bool startswith(const char *str, const char *prefix) {
    while (*prefix && *str == *prefix) {
        ++str;
        ++prefix;
    }
    return !*prefix;
}

/**
 * @brief Checks if the string `str` starts with `prefix` ignoring case
 */
static bool startswithcase(const char *str, const char *prefix) {
    return !strncasecmp(str, prefix, strlen(prefix));
}

/**
 * @brief Formats and sends a command using a printf format string `fmt`
 * with the following additional conversion specifiers:
 *  Specifier   Type           Description
 *  %!s         const char *   Formats a NUL-terminated string as an IMAP
 *                               literal.
 * Note: flags, conversion modifiers, etc. are not supported.
 * Returns 0 on success and -1 on failure.
 */
static int imap_send_cmd(IMAP_context *restrict ctx, const char *restrict fmt,
                         ...) {
    Network_socket *socket = ctx->socket;
    char response_buf[BUFFER_SIZE];
    va_list args;
    va_start(args, fmt);
    int offset = 0;
    ctx->outbuf[0] = '\0';
    int space = ctx->outbuf_sz - 1;

    while (*fmt) {
        switch (*fmt) {
        case '%':
            if (startswith(fmt, "%!s")) {
                const char *str = va_arg(args, const char *);

                snprintf(ctx->outbuf + offset, space, "{%lu}\r\n", strlen(str));
                socket->puts(socket->handle, ctx->outbuf);

                // wait for continue-req
                socket->gets(socket->handle, response_buf,
                             sizeof(response_buf));
                if (!startswith(response_buf, "+ ")) {
                    return -1;
                }

                // write string of CHAR8s
                int bytes = snprintf(ctx->outbuf, ctx->outbuf_sz, "%s", str);
                offset = bytes;
                space = ctx->outbuf_sz - bytes;

                fmt += 3;
            } else {
                // forward formatting to printf
                char convspec[4];
                int convspec_len = 2 + (fmt[1] == 'l');
                strncpy(convspec, fmt, convspec_len);
                int bytes =
                    vsnprintf(ctx->outbuf + offset, space, convspec, args);
                offset += bytes;
                space -= bytes;
                fmt += convspec_len;
            }
            break;

        default:
            ctx->outbuf[offset++] = *fmt++;
            ctx->outbuf[offset] = '\0';
            --space;
            break;
        }
    }
    va_end(args);

    if (offset) {
        socket->puts(socket->handle, ctx->outbuf);
    }

    return 0;
}

typedef struct {
    regex_t name;
    char *dst;
    int size;
} IMAP_header_field_options;

/**
 * @brief Returns -1 if the entire buffer has been read.
 *
 */
int parse_imap_headers(FILE *fp, IMAP_header_field_options *options,
                       int noptions, bool (*stop_condition)(void *, char *),
                       void *userdata) {
    char *line = NULL;
    size_t len = 0;

    regmatch_t matches[2];
    int matches_len = 2;

    // Process Body Header
    int nread;
    char *currdst = NULL;
    int currsize = 0;
    while ((nread = getline(&line, &len, fp)) != -1) {
        if (stop_condition(userdata, line)) {
            break;
        }

        // check for folded lines
        if (currdst && isspace(line[0])) {
            // remove the newline character
            line[strcspn(line, "\r\n")] = '\0';
            strncat(currdst, line, currsize);
            continue;
        }

        bool matched = false;
        for (int i = 0; i < noptions; ++i) {
            if (!regexec(&options[i].name, line, matches_len, matches, 0)) {
                currdst = options[i].dst;
                currsize = options[i].size;
                line[matches[1].rm_eo] = '\0';
                *currdst = '\0';
                strncat(currdst, line + matches[1].rm_so, currsize);

                matched = true;
                break;
            }
        }

        if (!matched) {
            currdst = NULL;
        }
    }

    free(line);

    return nread == -1 ? -1 : 0;
}

bool is_header_end(void *userdata, char *line) {
    (void)userdata;
    return !strcmp(line, "\r\n");
}

const char *imap_strerr(IMAP_ERRC errc) {
    switch (errc) {
    case IMAP_SUCCESS:
        return "Success";
    case IMAP_CONNECTION_ERROR:
        return "Connection error";
    case IMAP_LOGIN_FAILURE:
        return "Login failure";
    case IMAP_MESSAGE_NOT_FOUND:
        return "Message not found";
    case IMAP_FOLDER_NOT_FOUND:
        return "Folder not found";
    case IMAP_RETRIEVE_FAILURE:
        return "Message not found";
    case IMAP_MIME_ERROR:
        return "MIME format not supported";
    default:
        return "Unrecognized error code";
    }
}

bool is_valid_seqnum(const char *str) {
    if (!strcmp(str, "*")) {
        return true;
    }

    char *strend = NULL;
    // note: we use strtoll instead of strtoul since strtoul silently
    // accepts negative numbers
    int64_t seqnum = strtoll(str, &strend, 10);
    bool out_of_range = seqnum <= 0 || UINT32_MAX < seqnum;
    bool no_conversion = str == strend;
    bool has_trailing = (*strend) != 0;
    return !(out_of_range || no_conversion || has_trailing);
}

IMAP_context *create_imap_context(Network_socket *socket) {
    IMAP_context *con = malloc(sizeof(IMAP_context));
    *con = (IMAP_context){
        .socket = socket,
        .outbuf = malloc(INITIAL_WRITE_BUFFER_SIZE),
        .outbuf_sz = INITIAL_WRITE_BUFFER_SIZE,
    };
    return con;
}

void free_imap_context(IMAP_context *con) {
    free(con->outbuf);
    free(con);
}

IMAP_ERRC login(IMAP_context *restrict ctx, const char *username,
                const char *password) {
    Network_socket *socket = ctx->socket;
    char buffer[BUFFER_SIZE];

    if (imap_send_cmd(ctx, "A0001 LOGIN %!s %!s\r\n", username, password) < 0) {
        return IMAP_CONNECTION_ERROR;
    }

    if (socket->gets(socket->handle, buffer, BUFFER_SIZE) < 0) {
        return IMAP_CONNECTION_ERROR;
    }

    if (buffer[TAG_LENGTH + 1] == 'N') {
        return IMAP_LOGIN_FAILURE;
    }

    return IMAP_SUCCESS;
}

IMAP_ERRC select_folder(IMAP_context *restrict ctx,
                        const char *restrict folder) {
    Network_socket *socket = ctx->socket;
    char buffer[BUFFER_SIZE];

    if (imap_send_cmd(ctx, "A0002 SELECT %!s\r\n", folder) < 0) {
        return IMAP_CONNECTION_ERROR;
    }

    if (socket->gets(socket->handle, buffer, BUFFER_SIZE) < 0) {
        return IMAP_CONNECTION_ERROR;
    }

    if (buffer[TAG_LENGTH + 1] == 'N') {
        return IMAP_FOLDER_NOT_FOUND;
    }
    return IMAP_SUCCESS;
}

IMAP_ERRC retrieve(IMAP_context *restrict ctx, const char *messageNum) {
    Network_socket *socket = ctx->socket;

    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE, "A0003 FETCH %s BODY.PEEK[]\r\n", messageNum);

    if (socket->puts(socket->handle, buffer) == -1) {
        return IMAP_CONNECTION_ERROR;
    }

    // put socket into a file for read large response
    FILE *fp = fdopen(*(int *)socket->handle, "r");
    if (fp == NULL) {
        return IMAP_CONNECTION_ERROR;
    }
    char *line = NULL;
    size_t len = 0;

    if (getline(&line, &len, fp) == -1) {
        free(line);
        fclose(fp);
        return IMAP_CONNECTION_ERROR;
    }

    if (line[TAG_LENGTH + 1] == 'B') {
        free(line);
        fclose(fp);
        return IMAP_RETRIEVE_FAILURE;
    }
    if (line[TAG_LENGTH + 1] == 'N') {
        free(line);
        fclose(fp);
        return IMAP_RETRIEVE_FAILURE;
    }

    // print out the email content
    while (getline(&line, &len, fp) != -1) {
        // make sure handle when third last line is ")"
        if (startswith(line, "A0003 OK FETCH completed")) {
            break;
        }

        // check if reach the second last line's bracket before last line
        if (startswith(line, ")")) { // sees bracket, see if next line is end
            char *temp_line = NULL;
            size_t temp_len = 0;
            if (getline(&temp_line, &temp_len, fp) ==
                -1) { // if next line end, break
                free(temp_line);
                break;
            }
            if (!strncmp(temp_line, "A0003 OK Fetch completed", 24)) {
                free(temp_line);
                break;
            } else { // else just print out the 2 lines
                printf("%s", line);
                printf("%s", temp_line);
            }
            free(temp_line);
        } else {
            printf("%s", line);
        }
    }

    free(line);
    fclose(fp);
    return IMAP_SUCCESS;
}

IMAP_ERRC parse(IMAP_context *restrict ctx, const char *messageNum) {
    Network_socket *socket = ctx->socket;

    char from[BUFFER_SIZE] = "";
    char to[BUFFER_SIZE] = "";
    char date[BUFFER_SIZE] = "";
    char subject[BUFFER_SIZE] = " <No subject>";

    char buffer[BUFFER_SIZE];
    snprintf(
        buffer, BUFFER_SIZE,
        "A0004 FETCH %s BODY.PEEK[HEADER.FIELDS (FROM TO DATE SUBJECT)]\r\n",
        messageNum);

    if (socket->puts(socket->handle, buffer) == -1) {
        return IMAP_CONNECTION_ERROR;
    }

    // make socket a file
    FILE *fp = fdopen(*(int *)socket->handle, "r");
    if (fp == NULL) {
        return IMAP_CONNECTION_ERROR;
    }
    char *line = NULL;
    size_t len = 0;

    if (getline(&line, &len, fp) == -1) {
        free(line);
        return IMAP_CONNECTION_ERROR;
    }

    if (line[TAG_LENGTH + 1] == 'B') {
        free(line);
        return IMAP_RETRIEVE_FAILURE;
    }
    if (line[TAG_LENGTH + 1] == 'N') {
        free(line);
        return IMAP_RETRIEVE_FAILURE;
    }

    // extract header content
    int curr_arg = -1;
    while (getline(&line, &len, fp) != -1) {

        if (!strcmp(line, "\n") ||
            !strcmp(line, "\r\n")) { // finish if see empty line before ')'
            break;
        }

        if (line[0] == ' ' ||
            line[0] == '\t') { // this line belong to the same argument!
            line[strcspn(line, "\r\n")] = 0; // remove newline char
            if (curr_arg == 1) {
                strcat(from, line);
            } else if (curr_arg == 2) {
                strcat(to, line);
            } else if (curr_arg == 3) {
                strcat(date, line);
            } else if (curr_arg == 4) {
                strcat(subject, line);
            }
        }

        // read the from, to, date, subject lines
        if (startswithcase(line, "From:")) {
            curr_arg = 1;
            strcat(from, line + 5);
            from[strcspn(from, "\r\n")] = 0; // remove the newline character
        } else if (startswithcase(line, "To:")) {
            curr_arg = 2;
            strcat(to, line + 3);
            to[strcspn(to, "\r\n")] = 0; // remove the newline character
        } else if (startswithcase(line, "Date:")) {
            curr_arg = 3;
            strcat(date, line + 5);
            date[strcspn(date, "\r\n")] = 0; // remove the newline character
        } else if (startswithcase(line, "Subject:")) {
            curr_arg = 4;
            strcpy(subject, ""); // if no 'subject' it become default <..>
            strcat(subject, line + 8);
            subject[strcspn(subject, "\r\n")] =
                0; // remove the newline character
        }
    }

    // print headers
    printf("From:%s\n", from);
    printf("To:%s\n", to);
    printf("Date:%s\n", date);
    printf("Subject:%s\n", subject);

    free(line);
    fclose(fp);
    return IMAP_SUCCESS;
}

bool multipart_header_end(void *userdata, char *line) {
    char *boundary = userdata;
    return is_header_end(NULL, line) || startswith(line, boundary);
}

IMAP_ERRC mime(IMAP_context *restrict ctx, const char *messageNum) {
    Network_socket *socket = ctx->socket;

    // first finding boundary
    char boundary[BUFFER_SIZE] = {0};
    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE,
             "A0005 FETCH %s BODY.PEEK[HEADER.FIELDS (MIME-Version "
             "Content-type)]\r\n",
             messageNum);

    if (socket->puts(socket->handle, buffer) == -1) {
        return IMAP_CONNECTION_ERROR;
    }

    // make socket a file
    FILE *fp;
    fp = fdopen(*(int *)socket->handle, "r");
    if (fp == NULL) {
        return IMAP_CONNECTION_ERROR;
    }
    char *bline = NULL;
    size_t blen = 0;

    if (getline(&bline, &blen, fp) == -1) {
        free(bline);
        return IMAP_CONNECTION_ERROR;
    }

    if (bline[TAG_LENGTH + 1] == 'B') {
        free(bline);
        return IMAP_RETRIEVE_FAILURE;
    }
    if (bline[TAG_LENGTH + 1] == 'N') {
        free(bline);
        return IMAP_RETRIEVE_FAILURE;
    }
    free(bline);

    regex_t match_ctenc;
    regcomp(&match_ctenc, RMATCH_HEADER_FIELD("Content-Transfer-Encoding"),
            REG_ICASE);
    regex_t match_ctype;
    regcomp(&match_ctype, RMATCH_HEADER_FIELD("Content-Type"), REG_ICASE);
    regex_t match_mime;
    regcomp(&match_mime, RMATCH_HEADER_FIELD("MIME-Version"), REG_ICASE);

    // extract boundary
    {
        char content_type[BUFFER_SIZE] = {0};
        char mime_ver[BUFFER_SIZE] = {0};
        IMAP_header_field_options opts[] = {(IMAP_header_field_options){
                                                .name = match_mime,
                                                .size = BUFFER_SIZE,
                                                .dst = mime_ver,
                                            },
                                            (IMAP_header_field_options){
                                                .name = match_ctype,
                                                .size = BUFFER_SIZE,
                                                .dst = content_type,
                                            }};

        if (parse_imap_headers(fp, opts, sizeof(opts) / sizeof(*opts),
                               is_header_end, boundary) == -1) {
            return IMAP_MIME_ERROR;
        }

        if (strcmp(mime_ver, "1.0")) {
            return IMAP_MIME_ERROR;
        }

        if (!startswithcase(content_type, "multipart/alternative")) {
            return IMAP_MIME_ERROR;
        }

        regex_t get_boundary;
        regcomp(&get_boundary, "boundary=\"?([^\"]*)\"?",
                REG_ICASE | REG_EXTENDED);
        regmatch_t matches[2];
        if (!regexec(&get_boundary, content_type, 2, matches, 0)) {
            size_t boundary_len = matches[1].rm_eo - matches[1].rm_so;
            memcpy(boundary, content_type + matches[1].rm_so, boundary_len);
            boundary[boundary_len] = '\0';
        } else {
            return IMAP_MIME_ERROR;
        }
        regfree(&get_boundary);
    }

    // add "--" in front of boundary
    char temp_boundary[BUFFER_SIZE] = {0};
    snprintf(temp_boundary, BUFFER_SIZE, "--%s", boundary);
    strncpy(boundary, temp_boundary, BUFFER_SIZE - 1);
    boundary[BUFFER_SIZE - 1] = '\0';
    int boundary_len = strlen(boundary);

    // now get the whole message
    snprintf(buffer, BUFFER_SIZE, "A0006 FETCH %s BODY.PEEK[]\r\n", messageNum);

    if (socket->puts(socket->handle, buffer) == -1) {
        return IMAP_CONNECTION_ERROR;
    }

    // make socket a file
    fp = fdopen(*(int *)socket->handle, "r");
    if (fp == NULL) {
        return IMAP_CONNECTION_ERROR;
    }
    char *line = NULL;
    size_t len = 0;

    if (getline(&line, &len, fp) == -1) {
        free(line);
        return IMAP_CONNECTION_ERROR;
    }

    if (line[TAG_LENGTH + 1] == 'B') {
        free(line);
        return IMAP_RETRIEVE_FAILURE;
    }
    if (line[TAG_LENGTH + 1] == 'N') {
        free(line);
        return IMAP_RETRIEVE_FAILURE;
    }

    regex_t is_supported_ctenc;
    regcomp(&is_supported_ctenc, "(quoted-printable)?(7bit)?(8bit)?",
            REG_ICASE | REG_EXTENDED);

    regex_t is_supported_ctype;
    regcomp(&is_supported_ctype, "text/plain; charset=\"?UTF-8\"?",
            REG_ICASE | REG_EXTENDED);

    bool found_match = false;
    for (int counter = 0; counter < 10; ++counter) {
        // skip to the next boundary
        while (!startswith(line, boundary)) {
            if (getline(&line, &len, fp) == -1) {
                return IMAP_MIME_ERROR;
            }
        }

        // no more mime sections
        if (!strcmp(line + boundary_len, "--\r\n")) {
            break;
        }

        // Process Body Header
        char content_type[BUFFER_SIZE] = {0};
        char content_tenc[BUFFER_SIZE] = {0};
        IMAP_header_field_options opts[] = {(IMAP_header_field_options){
                                                .name = match_ctype,
                                                .size = BUFFER_SIZE,
                                                .dst = content_type,
                                            },
                                            (IMAP_header_field_options){
                                                .name = match_ctenc,
                                                .size = BUFFER_SIZE,
                                                .dst = content_tenc,
                                            }};

        if (parse_imap_headers(fp, opts, sizeof(opts) / sizeof(*opts),
                               multipart_header_end, boundary) == -1) {
            break;
        }

        // the default is 7bit which is supported
        regmatch_t rmatch;
        bool supported_content_tenc =
            *content_tenc
                ? !regexec(&is_supported_ctenc, content_tenc, 1, &rmatch, 0)
                : true;
        // the default text/plain with charset=UTF-8 which is not supported
        bool supported_content_type =
            *content_type
                ? !regexec(&is_supported_ctype, content_type, 1, &rmatch, 0)
                : false;

        // Process Body
        if (supported_content_tenc && supported_content_type) {
            found_match = true;
            char *prev_line = NULL;
            int prev_line_len = 0;
            while (getline(&line, &len, fp) != -1 &&
                   !startswith(line, boundary)) {
                if (prev_line) {
                    printf("%s", prev_line);
                }
                SWAP(prev_line, line);
                SWAP(prev_line_len, len);
            }
            free(prev_line);
            break;
        }
    }

    regfree(&is_supported_ctenc);
    regfree(&is_supported_ctype);

    regfree(&match_mime);
    regfree(&match_ctenc);
    regfree(&match_ctype);
    free(line);
    fclose(fp);

    return found_match ? IMAP_SUCCESS : IMAP_MIME_ERROR;
}

IMAP_ERRC list(IMAP_context *ctx) {
    Network_socket *socket = ctx->socket;

    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE,
             "A0134 FETCH 1:* BODY.PEEK[HEADER.FIELDS (SUBJECT)]\r\n");
    if (socket->puts(socket->handle, buffer) == -1) {
        return IMAP_CONNECTION_ERROR;
    }

    // make socket a file
    FILE *fp = fdopen(*(int *)socket->handle, "r");
    if (fp == NULL) {
        return IMAP_CONNECTION_ERROR;
    }
    char *line = NULL;
    size_t len = 0;

    regex_t match_subject;
    regcomp(&match_subject, RMATCH_HEADER_FIELD("Subject"), REG_ICASE);
    regex_t match_new_entry;
    regcomp(&match_new_entry, "\\* ([0-9]+) FETCH", REG_EXTENDED | REG_ICASE);

    regex_t should_stop;
    regcomp(&should_stop, "[^ ]+ OK", REG_EXTENDED | REG_ICASE);

    // extract header content
    while (getline(&line, &len, fp) != -1) {
        regmatch_t matches[2];
        if (!regexec(&should_stop, line, 2, matches, 0)) {
            break;
        }
        if (regexec(&match_new_entry, line, 2, matches, 0)) {
            continue;
        }
        for (int i = matches[1].rm_so; i < matches[1].rm_eo; ++i) {
            printf("%c", line[i]);
        }

        char subject[BUFFER_SIZE] = {0};
        IMAP_header_field_options opts[] = {
            (IMAP_header_field_options){
                .name = match_subject,
                .size = BUFFER_SIZE,
                .dst = subject,
            },
        };

        if (parse_imap_headers(fp, opts, sizeof(opts) / sizeof(*opts),
                               is_header_end, NULL) == -1) {
            return IMAP_CONNECTION_ERROR;
        }

        printf(": %s\n", *subject ? subject : "<No subject>");
    }

    regfree(&should_stop);
    regfree(&match_new_entry);
    regfree(&match_subject);

    free(line);
    fclose(fp);
    return IMAP_SUCCESS;
}