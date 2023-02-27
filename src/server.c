#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PATH_STATIC_FILES "www"

void error(char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
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
    puts("The program will open an HTTP server and serve static files out of the ./www directory");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printUsage(argv[1]);
        error("Invalid number of arguments.\n", -1);
    }

    // read the port from argv
    int port = atoi(argv[1]);
    if (port == 0) {
        error("Invalid port given as argument\n", -1);
    }

    // Generate the base path to the static files directory
    char path[1024];
    
    // Get the current working directory
    if (getcwd(path, sizeof(path)) == NULL) {
        perror("getcwd() error");
        error("Error getting current working directory.", -1);
    }

    // Append the static server directory to the path
    strcat(path, "/");
    strcat(path, PATH_STATIC_FILES);

    // Open a socket file descriptor and await connections
    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);


    while (1) {
        // Await connection
        // if connection: 
        // spawn a thread to handle the connection and service it

    }
}
