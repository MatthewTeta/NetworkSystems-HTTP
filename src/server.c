/**
 * HTTP Web server written in C
 * The server should accept GET request with HTTP version 1.0 or 1.1
 * The server will serve static files out of a folder named ./www relative to
 * the $CWD the server must support: .html .txt .png .gif .jpg .css .js It will
 * support the following error codes: 200 OK 400 Bad Request 403 Forbidden 404
 * Not Found 405 Method Not Allowed 505 HTTP Version Not Supported The server
 * will (ideally) support the "connection: keep-alive"
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Custom includes
#include "debug.h"

#define PATH_SEPARATOR        "/"
#define PATH_STATIC_FILES     "www"
#define MAX_PATH_SIZE         1024
#define BACKLOG               10
#define MAX_REQ_SIZE          8192
#define MAX_HEADER_LINES      4096
#define MAX_HEADER_SIZE       8192
#define MAX_ARB_BODY_SIZE     1024
#define KEEP_ALIVE_TIMEOUT_MS 10000

static int server_socketfd     = -1;
static int client_connectionfd = -1;
static int parent_process      = 1;
static int child_exit          = 0;

double get_elapsed_time(struct timeval start, struct timeval end) {
    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_usec - start.tv_usec) / 1000000.0;
    return elapsed;
}

void close_connection() {
    if (client_connectionfd != -1) {
        // Close the client socket
        close(client_connectionfd);
        client_connectionfd = -1;
    }
    // If this is a child process, exit
    if (!parent_process) {
        exit(0);
    }
}

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
struct http_status_code_map {
    http_status_code_t code;
    char              *message;
} HTTP_STATUS_CODES_MAP[] = {
    {HTTP_STATUS_OK, "OK"},
    {HTTP_STATUS_BAD_REQUEST, "Bad Request"},
    {HTTP_STATUS_FORBIDDEN, "Forbidden"},
    {HTTP_STATUS_NOT_FOUND, "Not Found"},
    {HTTP_STATUS_METHOD_NOT_ALLOWED, "Method Not Allowed"},
    {HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error"},
    {HTTP_STATUS_VERSION_NOT_SUPPORTED, "HTTP Version Not Supported"}};

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

struct ext_content_type {
    char               *ext;
    http_content_type_t type;
} HTTP_CONTENT_TYPES_EXT[] = {
    {".htm", HTTP_CONTENT_TYPE_HTML}, {".html", HTTP_CONTENT_TYPE_HTML},
    {".txt", HTTP_CONTENT_TYPE_TEXT}, {".png", HTTP_CONTENT_TYPE_PNG},
    {".gif", HTTP_CONTENT_TYPE_GIF},  {".jpg", HTTP_CONTENT_TYPE_JPG},
    {".css", HTTP_CONTENT_TYPE_CSS},  {".js", HTTP_CONTENT_TYPE_JS}};

typedef enum {
    HTTP_VERSION_INVALID = -1,
    HTTP_VERSION_1_0     = 0,
    HTTP_VERSION_1_1     = 1
} http_version_t;
char *HTTP_VERSIONS_SUPPORTED[] = {"HTTP/1.0", "HTTP/1.1"};

http_method         http_get_method(char *method);
http_version_t      http_get_version(char *version);
http_content_type_t http_get_content_type(char *file_name);
char               *http_get_status_message(http_status_code_t status);
int http_send_response(int connectionfd, char *message, FILE *infp,
                       http_version_t version, http_status_code_t status,
                       http_content_type_t content_type,
                       int connection_keep_alive, struct timeval start_time);
int http_send_bad_request(int connectionfd, http_version_t version,
                          struct timeval start_time, char *message, ...);

http_method http_get_method(char *method) {
    for (size_t i = 0; i < sizeof(HTTP_METHODS_SUPPORTED) / sizeof(char *);
         i++) {
        if (strcmp(method, HTTP_METHODS_SUPPORTED[i]) == 0) {
            return i;
        }
    }
    return -1;
}

http_version_t http_get_version(char *version) {
    for (size_t i = 0; i < sizeof(HTTP_VERSIONS_SUPPORTED) / sizeof(char *);
         i++) {
        if (strcmp(version, HTTP_VERSIONS_SUPPORTED[i]) == 0) {
            return i;
        }
    }
    return HTTP_VERSION_INVALID;
}

http_content_type_t http_get_content_type(char *file_name) {
    if (!file_name)
        return HTTP_CONTENT_TYPE_INVALID;
    char *file_ext = strrchr(file_name, '.');
    if (!file_ext)
        return HTTP_CONTENT_TYPE_INVALID;
    for (size_t i = 0; i < sizeof(HTTP_CONTENT_TYPES_EXT) / sizeof(char *);
         i++) {
        if (strcmp(file_ext, HTTP_CONTENT_TYPES_EXT[i].ext) == 0) {
            return HTTP_CONTENT_TYPES_EXT[i].type;
        }
    }
    return HTTP_CONTENT_TYPE_INVALID;
}

char *http_get_status_message(http_status_code_t status) {
    for (size_t i = 0; i < sizeof(HTTP_STATUS_CODES_MAP) / sizeof(char *);
         i++) {
        if (status == HTTP_STATUS_CODES_MAP[i].code) {
            return HTTP_STATUS_CODES_MAP[i].message;
        }
    }
    return NULL;
}

int http_send_response(int connectionfd, char *message, FILE *infp,
                       http_version_t version, http_status_code_t status,
                       http_content_type_t content_type,
                       int connection_keep_alive, struct timeval start_time) {
    if (connectionfd < 1) {
        return -1;
    }
    if (version == HTTP_VERSION_INVALID || status == HTTP_STATUS_INVALID) {
        return -2;
    }
    static char response_packet[MAX_HEADER_SIZE];
    memset(response_packet, 0, MAX_HEADER_SIZE);
    // Write the status line
    char *status_message = http_get_status_message(status);
    if (status_message == NULL) {
        return -5;
    }
    sprintf(response_packet, "%s %d %s\r\n", HTTP_VERSIONS_SUPPORTED[version],
            status, status_message);
    // Write the Content-Type header
    if (content_type != HTTP_CONTENT_TYPE_INVALID) {
        sprintf(response_packet + strlen(response_packet),
                "Content-Type: %s\r\n", HTTP_CONTENT_TYPES[content_type]);
    }
    // Write the Connection header
    if (connection_keep_alive) {
        strcat(response_packet, "Connection: keep-alive\r\n");
    } else {
        strcat(response_packet, "Connection: close\r\n");
    }
    // Write the Content-Length header
    // Get the length of the file from the file descriptor
    size_t body_len = 0;
    if (infp != NULL) {
        fseek(infp, 0, SEEK_END);
        body_len = ftell(infp);
        fseek(infp, 0, SEEK_SET);
    } else if (message != NULL) {
        body_len = strlen(message);
    }
    sprintf(response_packet + strlen(response_packet),
            "Content-Length: %lu\r\n", body_len);
    // Write a blank line to end the header
    strcat(response_packet, "\r\n");
    // Write the body
    size_t response_len = strlen(response_packet);
    size_t bytes_sent   = 0;
    // Send the response
    // Send the header
    while (bytes_sent < response_len) {
        ssize_t rv = send(connectionfd, response_packet + bytes_sent,
                          response_len - bytes_sent, 0);
        if (rv < 0) {
            return -3;
        }
        bytes_sent += (size_t)rv;
    }
    // Send the file body
    if (infp != NULL) {
        int   infd   = fileno(infp);
        off_t offset = 0;
        DEBUG_PRINT("Sending file body (fd: %d, len: %lu)\r\n", infd, body_len);
        bytes_sent = 0;
        while (bytes_sent < body_len) {
            int rv =
                sendfile(connectionfd, infd, &offset, body_len - bytes_sent);
            if (rv < 0) {
                return -4;
            }
            bytes_sent += (size_t)rv;
        }
    } else if (message != NULL) {
        // Send the message body
        bytes_sent         = 0;
        size_t message_len = strlen(message);
        DEBUG_PRINT("Sending %lu bytes\r\n", message_len);
        while (bytes_sent < message_len) {
            ssize_t rv = send(connectionfd, message + bytes_sent,
                              message_len - bytes_sent, 0);
            if (rv < 0) {
                return -6;
            }
            bytes_sent += (size_t)rv;
        }
    }
    // Log the response
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    double elapsed_time = get_elapsed_time(start_time, end_time) * 1000;
    printf("Response sent in %.2fms\r\n", elapsed_time);
    return 0;
}

int http_send_bad_request(int connectionfd, http_version_t version,
                          struct timeval start_time, char *message, ...) {
    va_list args;
    va_start(args, message);
    char *error_message = malloc(MAX_ARB_BODY_SIZE);
    vsnprintf(error_message, MAX_ARB_BODY_SIZE, message, args);
    va_end(args);
    int rv = http_send_response(connectionfd, error_message, NULL, version,
                                HTTP_STATUS_BAD_REQUEST, HTTP_CONTENT_TYPE_TEXT,
                                0, start_time);
    // Close the connection and exit the client
    close(client_connectionfd);
    fprintf(stderr, "Bad request -- %s\n", error_message);
    free(error_message);
    exit(-1);
    return rv;
}

// Linked list vector implementation for storing child processes pids
typedef struct pid_list {
    pid_t            pid;
    struct pid_list *next;
} pid_list_t;

pid_list_t *pid_list_create(pid_t pid) {
    pid_list_t *list = malloc(sizeof(pid_list_t));
    list->pid        = pid;
    list->next       = NULL;
    return list;
}

void pid_list_append(pid_list_t *list, pid_t pid) {
    if (list == NULL) {
        DEBUG_PRINT("Cannot append to NULL list\n");
        return;
    }
    pid_list_t *new_node = pid_list_create(pid);
    pid_list_t *current  = list;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}

pid_list_t *pid_list_remove(pid_list_t *list, pid_t pid) {
    if (list == NULL) {
        DEBUG_PRINT("Cannot remove from NULL list\n");
        return list;
    }
    pid_list_t *current = list;
    pid_list_t *prev    = NULL;
    while (current != NULL) {
        if (current->pid == pid) {
            if (prev == NULL) {
                // Removing the head
                DEBUG_PRINT("Removing head node\n");
                pid_list_t *next = current->next;
                free(current);
                current = next;
                return current;
            } else {
                // Removing a node in the middle
                DEBUG_PRINT("Removing node in the middle\n");
                prev->next = current->next;
                free(current);
                return list;
            }
        } else {
            prev    = current;
            current = current->next;
        }
    }
    return list;
}

void pid_list_free(pid_list_t *list) {
    pid_list_t *current = list;
    while (current != NULL) {
        pid_list_t *next = current->next;
        free(current);
        current = next;
    }
}

void pid_list_print(pid_list_t *list) {
    printf("CHILD PROCESSES: ");
    pid_list_t *current = list;
    while (current != NULL) {
        printf("%d ", current->pid);
        current = current->next;
    }
    printf("\n");
}

void error(int code, char *format, ...) {
    // Print the variadic args to stderr before exiting with code
    va_list argp;
    va_start(argp, format);
    vfprintf(stderr, format, argp);
    va_end(argp);

    close_connection();

    exit(code);
}

static pid_list_t *child_pids = NULL;

void sig_handler(int sig) {
    if (sig == SIGINT) {
        // Kill all child processes
        if (parent_process) {
            // Close the listening socket and tell all child processes to exit
            close(server_socketfd);
            // Mask the SIGCHLD signal so that it doesn't interrupt the waitpid
            // call
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            sigprocmask(SIG_BLOCK, &mask, NULL);
            pid_list_t *current = child_pids;
            while (current != NULL) {
                // KILL ALL THE CHILDREN
                kill(current->pid, SIGINT);
                current = current->next;
            }
            // Loop through the child pids and wait for them to exit
            printf("\nWaiting for child processes to exit gracefully...\n");
            current = child_pids;
            while (current != NULL) {
                int status;
                // REAP ALL THE CHILDREN
                waitpid(current->pid, &status, 0);
                current = current->next;
            }
            // Free the child pid list
            pid_list_free(child_pids);
            // Finally exit the parent process
            printf("Done\n");
            exit(0);
        } else {
            // Set a flag to indicate that the child process should exit after
            // the current request
            child_exit = 1;
        }
    } else if (sig == SIGCHLD) {
        if (parent_process) {
            DEBUG_PRINT("SIGCHLD received\n");
            // A child process has exited
            int   status;
            pid_t pid = waitpid(-1, &status, 0);
            if (pid > 0) {
                DEBUG_PRINT("Child process %d exited with status %d\n", pid,
                            status);
                // Remove the pid from the list of child pids
                child_pids = pid_list_remove(child_pids, pid);
            }
        }
    }
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

void strtolower(char *str) {
    for (size_t i = 0; i < strlen(str); i++) {
        str[i] = tolower(str[i]);
    }
}

void strtoupper(char *str) {
    for (size_t i = 0; i < strlen(str); i++) {
        str[i] = toupper(str[i]);
    }
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
    printf("Serving files on port %s out of static path: %s\n", port, path);
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
    server_socketfd =
        socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_socketfd < 0) {
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
    setsockopt(server_socketfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
               sizeof(int));
#endif

    rv = bind(server_socketfd, res->ai_addr, res->ai_addrlen);
    if (rv < 0) {
        perror("bind() failed");
        error(-1, "Error binding socket to port %s\n", port);
    }
    freeaddrinfo(res);

    // Begin listening for connections
    if (listen(server_socketfd, BACKLOG) < 0) {
        perror("listen() failed");
        error(-1, "Error listening on socket.\n");
    }

    // Handle SIGINT
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart interrupted system calls
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction(SIGINT) failed");
        error(-1, "Error setting up signal handler.\n");
    }
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction(SIGCHLD) failed");
        error(-1, "Error setting up signal handler.\n");
    }

    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t               client_addr_len;
        // Await connection
        client_addr_len     = sizeof(client_addr);
        client_connectionfd = accept(
            server_socketfd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_connectionfd < 0) {
            perror("accept() failed");
            continue;
        }
        // Fork into a new process to handle the connection
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork() failed");
            error(-1, "Error forking process.\n");
        } else if (pid > 0) {
            // Parent process
            DEBUG_PRINT("Forked child process: %d\n", pid);
            // Append the child process to the list of child processes
            if (child_pids == NULL) {
                child_pids = pid_list_create(pid);
            } else {
                pid_list_append(child_pids, pid);
            }
            // This bit is run in the parent process to accept new connections
            // Close the connection file descriptor in the parent process
            close_connection();
        } else if (pid == 0) {
            // Child process
            // Close the server socket file descriptor in the child process
            parent_process = 0;
            close(server_socketfd);
            server_socketfd = -1;
            // Get the client's address
            char           *hostaddrp;
            struct hostent *hostp;
            hostp = gethostbyaddr(
                (const char *)&((struct sockaddr_in *)&client_addr)
                    ->sin_addr.s_addr,
                sizeof(((struct sockaddr_in *)&client_addr)->sin_addr.s_addr),
                AF_INET);
            if (hostp == NULL) {
                error(-3, "ERROR on gethostbyaddr");
            }
            hostaddrp =
                inet_ntoa(((struct sockaddr_in *)&client_addr)->sin_addr);
            if (hostaddrp == NULL) {
                error(-3, "ERROR on inet_ntoa\n");
            }
            // Print who has connected
            printf("Established connectiong with %s (%s)\n", hostp->h_name,
                   hostaddrp);
            // This bit is run in the child process to handle the connection
            char header[MAX_REQ_SIZE + 1]; // +1 for null terminator
            // Get the time the connection was accepted
            struct timeval time_accept;
            gettimeofday(&time_accept, NULL);
            // Handle the connection
            while (!child_exit) {
                // Read the request
                memset(header, 0, MAX_REQ_SIZE + 1);
                int            received_header = 0;
                ssize_t        nread           = 0;
                size_t         header_len      = 0;
                struct timeval time_recv;
                // Read from the file descriptor until we reach the end of the
                // header, we read too much data, or we get an error such as a
                // timeout
                while (!received_header && header_len < MAX_REQ_SIZE) {
                    // Poll the socket for data until we get something or a
                    // timeout is recieved
                    short         revents = 0;
                    struct pollfd fds     = {
                            .fd      = client_connectionfd,
                            .events  = POLLIN,
                            .revents = revents,
                    };
                    int rv = poll(&fds, 1, KEEP_ALIVE_TIMEOUT_MS);
                    if (rv < 0) {
                        // This will fail if the parent recieves a SIGINT
                        // This is fine, check if nread is 0 to see if we have
                        // received any data If we have received data, continue
                        // processing the request If we have not received any
                        // data, exit the child process
                        if (nread)
                            break;
                        DEBUG_PRINT("Poll failed, exiting child process\n");
                        close_connection();
                    } else if (rv == 0) {
                        // Timeout -> close connection
                        close_connection();
                    }
                    // We got data before the timeout, read it
                    if (nread == 0) {
                        // Beginning of new header, get the time the header was
                        // received This is used to calculate the time it took
                        // to receive the header and send the response
                        gettimeofday(&time_recv, NULL);
                    }
                    if ((nread = recv(client_connectionfd, header + header_len,
                                      MAX_REQ_SIZE - header_len, 0)) < 0) {
                        perror("recv() failed");
                        error(-1, "Error receiving data from client.\n");
                    }
                    if (nread == 0) {
                        // The connection has been closed by the client
                        close_connection();
                    }
                    header_len += nread;
                    // Have we reached the end of the request?
                    // Loop through the buffer and check for the end of the
                    // header \r\n\r\n
                    size_t i;
                    for (i = 0; i < header_len - 3; i++) {
                        // Check for the end of the header
                        if (header[i] == '\r' && header[i + 1] == '\n' &&
                            header[i + 2] == '\r' && header[i + 3] == '\n') {
                            received_header = 1;
                            // If we were handling a body then we would
                            // rearrange the memory here Null terminate the
                            // header buffer We guarenteed an extra space for
                            // the null terminator by adding 1 to the header
                            // buffer size
                            if (i + 4 < MAX_REQ_SIZE) {
                                memset(header + i + 4, 0, MAX_REQ_SIZE - i - 4);
                            }
                            header[MAX_HEADER_SIZE] = '\0';
                        }
                    }
                    // Parse the request
                    DEBUG_PRINT("Received %ld bytes\n", nread);
                    // The request should be in the form:
                    // GET /path/to/file HTTP/<version>\r\n
                    // <headers>\r\n
                    // \r\n
                    // <body>
                    // Parse the request line
                    // Split the string based on \r
                }
                // Check for header too long
                if (!received_header && header_len == MAX_REQ_SIZE) {
                    http_send_bad_request(
                        client_connectionfd, HTTP_VERSION_1_1, time_recv,
                        "Header too long: Maximum Header length is %d bytes\n",
                        MAX_REQ_SIZE);
                    printf("Error parsing request. Header too long.\n");
                    close_connection();
                }
                // Check for connection closed
                if (nread == 0) {
                    DEBUG_PRINT("Connection closed by client\n");
                    close_connection();
                }
                // Parse the request line
                // Split the string based on \r\n delimiters
                char *lines[MAX_HEADER_LINES];
                if (split(header, lines, MAX_HEADER_LINES, "\r\n") ==
                    MAX_HEADER_LINES) {
                    http_send_bad_request(
                        client_connectionfd, HTTP_VERSION_1_1, time_recv,
                        "Invalid request: Too many lines in request header\n");
                }
                char *request_line = lines[0];
                // Parse the headers
                // Split the request line based on spaces
                char *tokens[3];
                if (split(request_line, tokens, 3, " ") != 3) {
                    http_send_bad_request(
                        client_connectionfd, HTTP_VERSION_1_1, time_recv,
                        "Invalid request line: %s\n", request_line);
                }
                char *method  = tokens[0];
                char *path    = tokens[1];
                char *version = tokens[2];
                strtoupper(method);
                strtoupper(version);
                printf("Method: %s\tPATH: %s\tVERSION: %s\n", method, path,
                       version);
                // Check the method
                if (HTTP_METHOD_INVALID == http_get_method(method)) {
                    http_send_bad_request(client_connectionfd, HTTP_VERSION_1_1,
                                          time_recv, "Invalid method: %s\n",
                                          method);
                }
                // Check the version
                http_version_t http_version = http_get_version(version);
                if (HTTP_VERSION_INVALID == http_version) {
                    http_send_bad_request(client_connectionfd, HTTP_VERSION_1_1,
                                          time_recv, "Invalid version: %s\n",
                                          version);
                }
                // Search for the connection header and determine where the body
                // starts (now I deleted the body above)
                int connection_keep_alive = 0;
                // char **body_start            = NULL;
                for (int i = 1; i < MAX_HEADER_LINES; i++) {
                    if (lines[i] == NULL)
                        break;
                    char *header = lines[i];
                    // Cast everything to lowercase
                    strtolower(header);
                    if (strncmp(header, "\r\n", 2) == 0) {
                        // The body starts after the empty line
                        // if (i + 1 < MAX_HEADER_LINES) {
                        //     body_start = &lines[i + 1];
                        // }
                        // Replace the empty line with a null terminator
                        lines[i] = NULL;
                        break;
                    }
                    if (strncmp(header, "connection: keep-alive", 22) == 0) {
                        connection_keep_alive = 1;
                        break;
                    }
                }
                // if (body_start == NULL) {
                //     printf("No body\n");
                // }
                if (connection_keep_alive) {
                    DEBUG_PRINT("Connection: keep-alive\n");
                }
                // No need to parse the body since we only do GET requests
                // Determine the file to serve
                // Concatenate the base path with the requested path
                char  file_path[MAX_PATH_SIZE];
                char *final_path = file_path;
                memset(file_path, 0, MAX_PATH_SIZE);
                snprintf(file_path, MAX_PATH_SIZE, "%s%s", PATH_STATIC_FILES,
                         path);
                // Attempt to open the file
                FILE *file = fopen(file_path, "r");
                DEBUG_PRINT("File path: %s\n", file_path);
                DIR *dir = opendir(file_path);
                if (file == NULL || dir != NULL) {
                    if (dir != NULL) {
                        closedir(dir);
                    }
                    // File does not exist
                    // Check if the path is a directory
                    // Add a trailing slash if it is not already present
                    if (file_path[strlen(file_path) - 1] != PATH_SEPARATOR[0]) {
                        strncat(file_path, PATH_SEPARATOR,
                                MAX_PATH_SIZE - strlen(file_path) - 1);
                        // break;
                    }
                    // Search for an index file
                    char index_path[MAX_PATH_SIZE];
                    for (size_t i = 0;
                         i < sizeof(PATH_FILE_NAME_DEFAULTS) / sizeof(char *);
                         i++) {
                        for (size_t j = 0;
                             j < sizeof(HTTP_CONTENT_TYPES_EXT) /
                                     sizeof(struct ext_content_type);
                             j++) {
                            memset(index_path, 0, MAX_PATH_SIZE);
                            snprintf(index_path, MAX_PATH_SIZE, "%s%s%s",
                                     file_path, PATH_FILE_NAME_DEFAULTS[i],
                                     HTTP_CONTENT_TYPES_EXT[j].ext);
                            file = fopen(index_path, "r");
                            if (file != NULL) {
                                // Found an index file
                                final_path = index_path;
                                goto file_found_maybe;
                            }
                        }
                    }
                }
            file_found_maybe:
                if (file == NULL) {
                    // File does not exist
                    // Generate a 404 response
                    rv = http_send_response(client_connectionfd,
                                            "File not found", NULL,
                                            http_version, HTTP_STATUS_NOT_FOUND,
                                            HTTP_CONTENT_TYPE_INVALID,
                                            connection_keep_alive, time_recv);
                    if (rv < 0) {
                        close(client_connectionfd);
                        error(-1, "Error sending response. (1) %d\n", rv);
                    }
                } else {
                    // Generate the response
                    // Send the response
                    rv = http_send_response(client_connectionfd, NULL, file,
                                            http_version, HTTP_STATUS_OK,
                                            http_get_content_type(final_path),
                                            connection_keep_alive, time_recv);
                    if (rv < 0) {
                        error(-1, "Error sending response. (2) %d\n", rv);
                    }
                    fclose(file);
                }
                // Close the connection if the request is not keep-alive
                if (!connection_keep_alive) {
                    close_connection();
                }
            }
            close_connection();
        }
    }
}