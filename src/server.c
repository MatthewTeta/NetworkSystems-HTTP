/**
 * HTTP Web server written in C
 * The server should accept GET request with HTTP version 1.0 or 1.1
 * The server will serve static files out of a folder named ./www relative to
 * the $CWD the server must support: .html .txt .png .gif .jpg .css .js It will
 * support the following error codes: 200 OK 400 Bad Request 403 Forbidden 404
 * Not Found 405 Method Not Allowed 505 HTTP Version Not Supported The server
 * will (ideally) support the "connection: keep-alive"
 */

#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
// #include <time.h>

// Custom includes
#include "debug.h"

#define PATH_SEPARATOR    "/"
#define PATH_STATIC_FILES "www"
#define MAX_PATH_SIZE     1024
#define BACKLOG           10
#define MAX_REQ_SIZE      1024
#define MAX_HEADER_LINES  100
#define MAX_FILE_SIZE     1024
#define MAX_HEADER_SIZE   1024
#define MAX_RES_SIZE      MAX_HEADER_SIZE + MAX_FILE_SIZE

// PATH FILE NAME DEFAULTS  - the names of files to search for if a directory is
// requested
char *PATH_FILE_NAME_DEFAULTS[] = {"index"};

typedef enum { HTTP_METHOD_INVALID = -1, HTTP_METHOD_GET = 0 } http_method;
char *HTTP_METHODS_SUPPORTED[] = {"GET"};

typedef enum {
    HTTP_STATUS_INVALID               = -1,
    HTTP_STATUS_OK                    = 200,
    HTTP_STATUS_BAD_REQUEST           = 400,
    HTTP_STATUS_FORBIDDEN             = 403,
    HTTP_STATUS_NOT_FOUND             = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED    = 405,
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_VERSION_NOT_SUPPORTED = 505
} http_status_code_t;
char *HTTP_STATUS_CODES[] = {"200 OK",
                             "400 Bad Request",
                             "403 Forbidden",
                             "404 Not Found",
                             "405 Method Not Allowed",
                             "500 Internal Server Error",
                             "505 HTTP Version Not Supported"};

typedef enum {
    HTTP_CONTENT_TYPE_INVALID = -1,
    HTTP_CONTENT_TYPE_HTML    = 0,
    HTTP_CONTENT_TYPE_TEXT    = 1,
    HTTP_CONTENT_TYPE_PNG     = 2,
    HTTP_CONTENT_TYPE_GIF     = 3,
    HTTP_CONTENT_TYPE_JPG     = 4,
    HTTP_CONTENT_TYPE_CSS     = 5,
    HTTP_CONTENT_TYPE_JS      = 6
} http_content_type_t;
char *HTTP_CONTENT_TYPES[] = {"text/html",      "text/plain", "image/png",
                              "image/gif",      "image/jpeg", "text/css",
                              "text/javascript"};

typedef enum {
    HTTP_VERSION_INVALID = -1,
    HTTP_VERSION_1_0     = 0,
    HTTP_VERSION_1_1     = 1
} http_version_t;
char *HTTP_VERSIONS_SUPPORTED[] = {"HTTP/1.0", "HTTP/1.1"};

struct ext_content_type {
    char               *ext;
    http_content_type_t type;
} ext_content_type_t;

struct ext_content_type HTTP_CONTENT_TYPES_EXT[] = {
    {".htm", HTTP_CONTENT_TYPE_HTML}, {".html", HTTP_CONTENT_TYPE_HTML},
    {".txt", HTTP_CONTENT_TYPE_TEXT}, {".png", HTTP_CONTENT_TYPE_PNG},
    {".gif", HTTP_CONTENT_TYPE_GIF},  {".jpg", HTTP_CONTENT_TYPE_JPG},
    {".css", HTTP_CONTENT_TYPE_CSS},  {".js", HTTP_CONTENT_TYPE_JS}};

http_method         http_get_method(char *method);
http_version_t      http_get_version(char *version);
http_content_type_t http_get_content_type(char *file_name);
int http_send_response(int connectionfd, char *body, size_t body_size,
                       http_version_t version, http_status_code_t status,
                       http_content_type_t content_type,
                       int                 connection_keep_alive);

http_method http_get_method(char *method) {
    for (int i = 0; i < (int)sizeof(HTTP_METHODS_SUPPORTED); i++) {
        if (strcmp(method, HTTP_METHODS_SUPPORTED[i]) == 0) {
            return i;
        }
    }
    return -1;
}

http_version_t http_get_version(char *version) {
    for (int i = 0; i < (int)sizeof(HTTP_VERSIONS_SUPPORTED); i++) {
        if (strcmp(version, HTTP_VERSIONS_SUPPORTED[i]) == 0) {
            return i;
        }
    }
    return -1;
}

http_content_type_t http_get_content_type(char *file_name) {
    if (!file_name)
        return HTTP_CONTENT_TYPE_INVALID;
    char *file_ext = strrchr(file_name, '.');
    if (!file_ext)
        return HTTP_CONTENT_TYPE_INVALID;
    for (int i = 0; i < (int)sizeof(HTTP_CONTENT_TYPES_EXT); i++) {
        if (strcmp(file_ext, HTTP_CONTENT_TYPES_EXT[i].ext) == 0) {
            return HTTP_CONTENT_TYPES_EXT[i].type;
        }
    }
    return HTTP_CONTENT_TYPE_INVALID;
}

int http_send_response(int connectionfd, char *body, size_t body_len,
                       http_version_t version, http_status_code_t status,
                       http_content_type_t content_type,
                       int                 connection_keep_alive) {
    if (connectionfd < 1 || body == NULL || body_len > MAX_FILE_SIZE) {
        return -1;
    }
    if (version == HTTP_VERSION_INVALID || status == HTTP_STATUS_INVALID ||
        content_type == HTTP_CONTENT_TYPE_INVALID) {
        return -1;
    }
    static char response_packet[MAX_RES_SIZE];
    memset(response_packet, 0, MAX_RES_SIZE);
    // Write the status line
    sprintf(response_packet, "%s %d %s\r\n", HTTP_VERSIONS_SUPPORTED[version],
            status, HTTP_STATUS_CODES[status]);
    // TODO: Write the Content-Type header
    // TODO: Write the Content-Length header
    // Write the Connection header
    if (connection_keep_alive) {
        sprintf(response_packet, "Connection: keep-alive\r\n");
    } else {
        sprintf(response_packet, "Connection: close\r\n");
    }
    // Write a blank line to end the header
    sprintf(response_packet, "\r\n");
    // Write the body
    size_t response_len = strlen(response_packet);
    if (status == HTTP_STATUS_OK) {
        memcpy(response_packet, body, body_len);
    }
    response_len += body_len;
    // Send the response
    return send(connectionfd, response_packet, response_len, 0);
}

void error(int code, char *format, ...) {
    // fprintf(stderr, __VA_ARGS__);
    // Print the variadic args to stderr before exiting with code
    va_list argp;
    va_start(argp, format);
    vfprintf(stderr, format, argp);
    va_end(argp);

    exit(code);
}

void sigint_handler(int sig) {
    if (sig == SIGINT) {
        // Cancel any ongoing ftp transaction
        // TODO: Exit all threads with a sentinal
    }
    exit(-1);
}

/**
 * Split a string into an array of strings based on a delimiter
 * @param  buffer     The string to split
 * @param  delimiter  The delimiter to split on
 * @param  lines      The array of strings to store the split strings in
 * @param  max_lines  The maximum number of lines to split the string into
 * @return            The number of lines split or -1 if the max_lines was
 * exceeded
 */
int split(char *buffer, char **lines, int max_lines, char *delimiter) {
    if (buffer == NULL || delimiter == NULL || lines == NULL) {
        return -1;
    }
    memset(lines, 0, max_lines * sizeof(char *));
    int   i = 0;
    char *line;
    line = strtok(buffer, delimiter);
    while (line != NULL && i < max_lines) {
        lines[i] = line;
        line     = strtok(NULL, delimiter);
        i++;
    }
    return i;
}

void printUsage(char *prog_name) {
    printf("Usage: %s <port>\n", prog_name);
    puts("The program will open an HTTP server and serve static files out "
         "of "
         "the ./www directory");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printUsage(argv[1]);
        error(-1, "Invalid number of arguments.\n");
    }

    // read the port from argv
    char *port = argv[1];
    if (atoi(port) == 0) {
        error(-1, "Invalid port given as argument\n");
    }

    // Generate the base path to the static files directory
    char path[1024];
    // Get the current working directory
    if (getcwd(path, sizeof(path)) == NULL) {
        perror("getcwd() error");
        error(-1, "Error getting current working directory.\n");
    }
    // Append the static server directory to the path
    strcat(path, "/");
    strcat(path, PATH_STATIC_FILES);
    DEBUG_PRINT("Serving files out of static path: %s\n", path);
    // Check if the directory exists and exit if not
    DIR *dir = opendir(path);
    if (dir) {
        // Directory exists
        closedir(dir);
    } else if (ENOENT == errno) {
        // Directory does not exist
        error(-1, "Static files directory does not exist.\n");
    } else {
        // opendir() failed for some other reason
        error(-1, "Error opening static files directory.\n");
    }

    // Setup the space for the address info
    struct addrinfo  hints;
    struct addrinfo *res;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags    = AI_PASSIVE;  /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP; /* Any protocol */
    // Get the address info for the given port
    int rv = getaddrinfo(NULL, port, &hints, &res);
    if (rv != 0) {
        perror("getaddrinfo() failed");
        error(-1, "Error getting address info for port %s -- %s\n", port,
              gai_strerror(rv));
    }

    // Open a socket file descriptor and await connections
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket() failed");
        error(-1, "Error opening socket.\n");
    }

#ifdef DEBUG
    /* setsockopt: Handy debugging trick that lets
     * us rerun the server immediately after we kill it;
     * otherwise we have to wait about 20 secs.
     * Eliminates "ERROR on binding: Address already in use" error.
     */
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
               sizeof(int));
#endif

    rv = bind(sock, res->ai_addr, res->ai_addrlen);
    if (rv < 0) {
        perror("bind() failed");
        error(-1, "Error binding socket to port %s\n", port);
    }

    // Begin listening for connections
    if (listen(sock, BACKLOG) < 0) {
        perror("listen() failed");
        error(-1, "Error listening on socket.\n");
    }

    // TODO: Handle SIGINT

    struct sockaddr_storage client_addr;
    socklen_t               client_addr_len;
    char                    buffer[MAX_REQ_SIZE];
    int                     nread;
    // while (1) {
    // Await connection
    client_addr_len = sizeof(client_addr);
    int connection =
        accept(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    // if connection:
    if (connection < 0) {
        perror("accept() failed");
        error(-1, "Error accepting connection.\n");
    }
    // Handle the connection
    while (1) {
        // Read the request
        // This should be in a loop to handle partial reads
        if ((nread = recv(connection, buffer, sizeof(buffer), 0)) < 0) {
            perror("recv() failed");
            error(-1, "Error receiving data from client.\n");
        }
        // Have we reached the end of the request?
        if (nread == 0) {
            // The connection has been closed
            break;
        }
        // Parse the request
        printf("Received %d bytes:\n%s\n", nread, buffer);
        // The request should be in the form:
        // GET /path/to/file HTTP/<version>\r\n
        // <headers>\r\n
        // \r\n
        // <body>
        // Parse the request line
        // Split the string based on \r\n delimiters
        char *lines[MAX_HEADER_LINES];
        if (split(buffer, lines, MAX_HEADER_LINES, "\r\n") ==
            MAX_HEADER_LINES) {
            error(-1, "Error parsing request. Too many lines in request\n");
        }
        char *request_line = lines[0];
        // Parse the headers
        // Split the request line based on spaces
        char *tokens[3];
        if (split(request_line, tokens, 3, " ") != 3) {
            error(-1, "Error parsing request line.\n");
        }
        char *method  = tokens[0];
        char *path    = tokens[1];
        char *version = tokens[2];
        printf("Method: %s\n", method);
        printf("Path: %s\n", path);
        printf("Version: %s\n", version);
        // TODO: Respond with 400 Bad Request if the request line is invalid
        // Check the method
        if (HTTP_METHOD_INVALID == http_get_method(method)) {
            error(-1, "Error parsing request. Invalid method.\n");
        }
        // Check the version
        http_version_t http_version = http_get_version(version);
        if (HTTP_VERSION_INVALID == http_version) {
            error(-1, "Error parsing request. Invalid version.\n");
        }
        // Search for the connection header and determine where the body
        // starts
        int    connection_keep_alive = 0;
        char **body_start            = NULL;
        for (int i = 1; i < MAX_HEADER_LINES; i++) {
            if (lines[i] == NULL)
                break;
            char *header = lines[i];
            if (strncmp(header, "\r\n", 2) == 0) {
                // The body starts after the empty line
                if (i + 1 < MAX_HEADER_LINES) {
                    body_start = &lines[i + 1];
                }
                // Replace the empty line with a null terminator
                lines[i] = NULL;
                break;
            }
            if (strncmp(header, "Connection: keep-alive", 22) == 0) {
                connection_keep_alive = 1;
                break;
            }
        }
        if (body_start == NULL) {
            printf("No body\n");
        }
        if (connection_keep_alive) {
            printf("Connection keep-alive\n");
        }
        // No need to parse the body since we only do GET requests
        // Determine the file to serve
        // Concatenate the base path with the requested path
        char file_path[MAX_PATH_SIZE];
        memset(file_path, 0, MAX_PATH_SIZE);
        snprintf(file_path, MAX_PATH_SIZE, "%s%s", PATH_STATIC_FILES, path);
        // Attempt to open the file
        FILE *file = fopen(file_path, "r");
        printf("File path: %s\n", file_path);
        printf("File: %p\n", file);
        if (file == NULL) {
            // File does not exist
            // Check if the path is a directory
            // Append a trailing slash if it is not already present
            if (file_path[strlen(file_path) - 1] != PATH_SEPARATOR[0]) {
                strncat(file_path, PATH_SEPARATOR, MAX_PATH_SIZE - strlen(file_path) - 1);
            }
            // Search for an index file
            char index_path[MAX_PATH_SIZE];
            printf("SIZEOF: %lu\n", sizeof(PATH_FILE_NAME_DEFAULTS));
            for (size_t i; i < sizeof(PATH_FILE_NAME_DEFAULTS); i++) {
                printf("Trying %s%s\n", file_path, PATH_FILE_NAME_DEFAULTS[i]);
                for (size_t j; j < sizeof(HTTP_CONTENT_TYPES_EXT); j++) {
                    memset(index_path, 0, MAX_PATH_SIZE);
                    snprintf(index_path, MAX_PATH_SIZE, "%s%s%s", file_path,
                             PATH_FILE_NAME_DEFAULTS[i],
                             HTTP_CONTENT_TYPES_EXT[j].ext);
                    printf("Trying %s\n", index_path);
                    file = fopen(index_path, "r");
                    if (file != NULL) {
                        // Found an index file
                        goto file_found;
                    }
                }
            }
        }
        file_found:
        if (file == NULL) {
            // File does not exist
            // Generate a 404 response
            rv = http_send_response(
                connection, NULL, 0, http_version, HTTP_STATUS_NOT_FOUND,
                HTTP_CONTENT_TYPE_TEXT, connection_keep_alive);
            if (rv < 0) {
                error(-1, "Error sending response.\n");
            }
            // Send the response
            // Close the connection if the request is not keep-alive
            break;
            // error(-1, "Error opening file %s\n", file_path);
        }
        // Read the file
        char   file_buffer[MAX_FILE_SIZE];
        size_t file_size = fread(file_buffer, 1, MAX_FILE_SIZE, file);
        if (file_size == 0) {
            error(-1, "Error reading file %s\n", file_path);
        }
        fclose(file);
        // Generate the response
        // Send the response
        rv = http_send_response(
            connection, file_buffer, file_size, http_version, HTTP_STATUS_OK,
            http_get_content_type(file_path), connection_keep_alive);
        if (rv < 0) {
            error(-1, "Error sending response.\n");
        }
        // Close the connection if the request is not keep-alive
        if (!connection_keep_alive) {
            break;
        }
    }

    // Close the connection
    close(connection);

    // spawn a thread to handle the connection and service it
    // }
}
