/*
 * WebSrv - Simple, buggy web server
 *
 * (c) 2015 Samuel Groß
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define PORT 80
#define TIMEOUT 120
#define CRLF "\r\n"
#define CRLF2 "\r\n\r\n"
#define WEBROOT "webroot/"

struct sockaddr_in client;
char buf[2048];
ssize_t bufsz;

int die(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(-1);
}

void wait_for_child(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_alarm(int sig)
{
    puts("Client timed out...");
    exit(0);
}


void http_send(int socket, const char *fmt, ...)
{
    char msg[2048], *pos;
    va_list args;

    memset(msg, 0, sizeof(msg));

    va_start(args, fmt);
    vsprintf(msg, fmt, args);
    va_end(args);

    send(socket, msg, strlen(msg), 0);
}

int send_error(int socket, int code, const char* msg)
{
    char* body = ""
"<html>\n"
"  <head>\n"
"    <title>No.</title>\n"
"  </head>\n"
"  <body>\n"
"    <center><h1>%d %s</h1></center>\n"
"    <hr><center>Super Secure Web Server v.3.1.33.7</center>\n"
"  </body>\n"
"</html>";

    http_send(socket, "HTTP/1.1 %d %s" CRLF, code, msg);
    http_send(socket, "Content-Type: text/html" CRLF);
    http_send(socket, "Content-Length: %d" CRLF2, strlen(body) + 3 + strlen(msg) - 4);
    http_send(socket, body, code, msg);

    return code;
}

int handle_led_cmd(int socket, char* cmd)
{
    if (strcmp(cmd, "ledon") == 0)
	system("./led on");
    else
	system("./led off");

    char* body = "OK";
    http_send(socket, "HTTP/1.1 200 OK" CRLF);
    http_send(socket, "Content-Length: %d" CRLF2, strlen(body));
    http_send(socket, "%s", body);

    return 200;
}

int handle_req(int socket, char* request, size_t len)
{
    FILE* f;
    long fsize;
    char buf[2048], *file, *fend;

    if (memcmp(request, "GET", 3) != 0) {
        return send_error(socket, 501, "Not Implemented");
    }

    /*
     * Determine requested file
     */
    file = request + 4;
    fend = memchr(file, ' ', len-4);
    if (!fend)
        return send_error(socket, 400, "Bad Request");

    *fend = 0;

    if (strcmp(file, "/") == 0)
        file = "index.html";

    if (strcmp(file, "/ledon") == 0 || strcmp(file, "/ledoff") == 0)
	return handle_led_cmd(socket, file+1);

    printf("%s:%d request for file '%s'\n", inet_ntoa(client.sin_addr), htons(client.sin_port), file);

    strcpy(buf, WEBROOT);
    strcat(buf, file);

    /*
     * Open file
     */
    f = fopen(buf, "r");
    if (!f)
        return send_error(socket, 404, "Not Found");
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, 0);

    /*
     * Send header
     */
    http_send(socket, "HTTP/1.1 200 OK" CRLF);
    http_send(socket, "Content-Type: text/html" CRLF);
    http_send(socket, "Content-Length: %d" CRLF2, fsize);

    /*
     * Send body
     */
    while ((len = fread(buf, 1, sizeof(buf), f)) > 0) {
        send(socket, buf, len, 0);
    }

    fclose(f);

    return 200;
}

int handle_single_request(int socket)
{
    ssize_t len, cntlen;
    char req[4096];
    char *ptr, *pos;

    /*
     * Read Header
     */
    ptr = req;
    while (1) {
        // we could write directly into 'ptr', but this makes reversing a bit more interesting I guess
        if (bufsz == 0) {
    	    bufsz = recv(socket, buf, sizeof(buf), 0);
    	    if (bufsz <= 0)
    	        return -1;
        }
        
        memcpy(ptr, buf, bufsz);
        ptr += bufsz;
        bufsz = 0;

        pos = memmem(req, ptr - req, CRLF2, 4);
        if (pos) {
            bufsz = ptr - (pos + 4);
            ptr = pos + 4;
    	    memcpy(buf, ptr, bufsz);
            *ptr = 0; 			// make it a c string
    	    break;
        }
    }

    /*
     * Read Body
     */
    pos = strcasestr(req, "Content-Length:");
    if (pos) {
        pos += 15;
        while (isspace(*pos)) pos++;
        cntlen = atoi(pos);
        
        while (cntlen > 0) {
            if (bufsz == 0) {
    	        len = recv(socket, ptr, cntlen, 0);
    	        if (len <= 0)
    	            return -1;

                cntlen -= len;
                ptr += len;
            } else {
                len = min(bufsz, cntlen);
                memcpy(ptr, buf, len);

                ptr += len;
                cntlen -= len;
                bufsz -= len;

                if (bufsz != 0) {
                    memmove(buf, buf + len, bufsz);
                }
            }
        }
    }

    /*
     * Process Request
     */
    return handle_req(socket, req, ptr - req);
}

void handle_client(int socket)
{
    int code, reqcount = 0;

    while (1) {
        reqcount++;
        code = handle_single_request(socket);
        if (code < 0) return;
        printf("%s:%d request #%d => %d\n", inet_ntoa(client.sin_addr), htons(client.sin_port), reqcount, code);
    }
}

int main()
{
    int sockfd, clientfd, pid;
    unsigned int clilen;
    struct sockaddr_in serv_addr;
    struct sigaction sa;

    /*
     * Set up the signal handlers
     */
    sa.sa_handler = wait_for_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        die("sigaction() failed: %s\n", strerror(errno));
    sa.sa_handler = handle_alarm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGALRM, &sa, NULL) == -1)
        die("sigaction() failed: %s\n", strerror(errno));

    /*
     * Set up socket
     */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        die("socket() failed: %s\n", strerror(errno));

    int val = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1)
	die("setsockopt() failed with %s\n", strerror(errno));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        die("bind() failed: %s\n", strerror(errno));

    if (listen(sockfd, 5) == -1)
        die("listen() failed: %s\n", strerror(errno));

    /*
     * Server loop
     */
    while (1) {
        clilen = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr*)&client, &clilen);
        if (clientfd < 0)
            die("accept() failed: %s\n", strerror(errno));

        printf("New connection from %s on port %d\n", inet_ntoa(client.sin_addr), htons(client.sin_port));

        pid = fork();
        if (pid < 0) {
            die("fork() failed: %s\n", strerror(errno));
        } else if (pid == 0) {
            /*
             * TODO: Even though we use CAP_NET_BIND_SERVICE we might still want to drop privs so child can't interfere with parent
             */
            close(sockfd);
            alarm(TIMEOUT);
            handle_client(clientfd);
            printf("%s:%d disconnected\n", inet_ntoa(client.sin_addr), htons(client.sin_port));
            close(clientfd);
            exit(0);
        } else {
            close(clientfd);
        }

    }

    return 0;
}
