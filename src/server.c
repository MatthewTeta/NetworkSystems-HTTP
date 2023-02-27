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

#define PATH_STATIC_FILES "www"

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

void printUsage(char *prog_name) {
    printf("Usage: %s <port>\n", prog_name);
    puts("The program will open an HTTP server and serve static files out of "
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

    while (1) {
        // Await connection
        // if connection:
        // spawn a thread to handle the connection and service it
    }
}
