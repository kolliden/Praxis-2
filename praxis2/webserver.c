#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "data.h"
#include "http.h"
#include "util.h"

#define MAX_RESOURCES 100

typedef struct __attribute__((__packed__)) lookup_message
{
    uint8_t msg_type; // 0 = Lookup
    uint16_t hash_id;
    uint16_t node_id;
    uint32_t ip;
    uint16_t port;
} lookup_message_t;

struct tuple resources[MAX_RESOURCES] = {
    {"/static/foo", "Foo", sizeof "Foo" - 1},
    {"/static/bar", "Bar", sizeof "Bar" - 1},
    {"/static/baz", "Baz", sizeof "Baz" - 1}};

/* --- Node / neighborhood configuration (populated at startup) --- */

static uint16_t NODE_ID = 0;
static uint32_t NODE_IP = 0;
static uint16_t NODE_PORT = 0;
static uint16_t PRED_ID = 0;
static uint16_t SUCC_ID = 0;
static char PRED_IP[INET_ADDRSTRLEN] = {0};
static char PRED_PORT[6] = {0};
static char SUCC_IP[INET_ADDRSTRLEN] = {0};
static char SUCC_PORT[6] = {0};

/**
 * Derives a sockaddr_in structure from the provided host and port information.
 *
 * @param host The host (IP address or hostname) to be resolved into a network
 * address.
 * @param port The port number to be converted into network byte order.
 *
 * @return A sockaddr_in structure representing the network address derived from
 * the host and port.
 */
static struct sockaddr_in derive_sockaddr(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family = AF_INET,
    };
    struct addrinfo *result_info;

    // Resolve the host (IP address or hostname) into a list of possible
    // addresses.
    int returncode = getaddrinfo(host, port, &hints, &result_info);
    if (returncode)
    {
        fprintf(stderr, "Error parsing host/port");
        exit(EXIT_FAILURE);
    }

    // Copy the sockaddr_in structure from the first address in the list
    struct sockaddr_in result = *((struct sockaddr_in *)result_info->ai_addr);

    // Free the allocated memory for the result_info
    freeaddrinfo(result_info);
    return result;
}

static bool is_responsible(uint16_t key, uint16_t node_id, uint16_t pred_id)
{
    if (pred_id == node_id)
        return true; /* single-node circle */
    if (pred_id < node_id)
        return (key > pred_id && key <= node_id);
    return (key > pred_id || key <= node_id); /* wrap-around */
}

static bool knows_responsible_node(uint16_t key)
{
    return is_responsible(key, NODE_ID, PRED_ID) || (NODE_ID == SUCC_ID) || (PRED_ID == SUCC_ID);
}
/**
 * The function `send_udp_message` sends a UDP message to a specified IP address and port.
 *
 * @param msg The `msg` parameter in the `send_udp_message` function is of type `lookup_message_t *`,
 * which is a pointer to a `lookup_message_t` struct. This struct likely contains information needed
 * for the UDP message being sent, such as data to be transmitted.
 * @param ip The `ip` parameter in the `send_udp_message` function is a pointer to a string that
 * represents the IP address to which the UDP message will be sent.
 * @param port The `port` parameter in the `send_udp_message` function is a pointer to a constant
 * character string that represents the port number to which the UDP message will be sent. It is used
 * to specify the destination port for the UDP communication.
 *
 * @return If the `socket` function fails and returns -1, an error message will be printed using
 * `perror("socket")` and the function will return without sending the UDP message. Similarly, if the
 * `sendto` function fails and returns -1, an error message will be printed using `perror("sendto")`
 * and the function will return without closing the socket.
 */
static void send_udp_message(lookup_message_t *msg, const char *ip, const char *port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        perror("socket");
        return;
    }
    struct sockaddr_in addr = derive_sockaddr(ip, port);
    ssize_t send_bytes = sendto(sock, msg, sizeof(*msg), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (send_bytes == -1)
    {
        perror("sendto");
        return;
    }
    close(sock);
}

/**
 * The function `send_lookup` sends a lookup message containing key, type, IP, and port information
 * over UDP.
 *
 * @param key The `key` parameter is a 16-bit unsigned integer used as a lookup key in the
 * `send_lookup` function.
 * @param type The `type` parameter in the `send_lookup` function represents the type of lookup message
 * being sent. It is of type `uint8_t`, which means it is an unsigned 8-bit integer. This parameter is
 * used to specify the type of the message being sent, such as a lookup request
 * @param ip The `ip` parameter in the `send_lookup` function is a pointer to a character array that
 * represents the IP address to which the lookup message will be sent. It should be a valid IPv4 or
 * IPv6 address in string format.
 * @param port The `port` parameter in the `send_lookup` function is a pointer to a character array
 * that represents the port number to which the UDP message will be sent. The port number is typically
 * a 16-bit unsigned integer value that specifies the port on the destination host where the message
 * should be delivered.
 */
static void send_lookup(uint16_t key, uint8_t type, const char *ip, const char *port) // Aufgabe 1.3 Senden eines Lookup
{
    lookup_message_t msg = {
        .msg_type = type,
        .hash_id = htons(key),
        .node_id = htons(NODE_ID),
        .ip = htonl(NODE_IP),
        .port = htons(NODE_PORT),
    };
    send_udp_message(&msg, ip, port);
}

/**
 * Sends an HTTP reply to the client based on the received request.
 *
 * @param conn      The file descriptor of the client connection socket.
 * @param request   A pointer to the struct containing the parsed request
 * information.
 */
void send_reply(int conn, struct request *request)
{

    // Create a buffer to hold the HTTP reply
    char buffer[HTTP_MAX_SIZE];
    char *reply = buffer;
    size_t offset = 0;

    fprintf(stderr, "Handling %s request for %s (%lu byte payload)\n",
            request->method, request->uri, request->payload_length);

    uint16_t key = pseudo_hash((const unsigned char *)request->uri, strlen(request->uri)); // Aufgabe 1.2 Hashing
    fprintf(stderr, "Computed key (pseudo-hash) = %u (0x%04x)\n", (unsigned)key, (unsigned)key);

    if (!is_responsible(key, NODE_ID, PRED_ID) && knows_responsible_node(key))
    {
        /* Build Location: http://SUCC_IP:SUCC_PORT<uri> */
        int n = snprintf(buffer, sizeof(buffer),
                         "HTTP/1.1 303 See Other\r\n"
                         "Location: http://%s:%s%s\r\n"
                         "Content-Length: 0\r\n"
                         "\r\n",
                         SUCC_IP[0] ? SUCC_IP : "127.0.0.1",
                         SUCC_PORT[0] ? SUCC_PORT : "80", request->uri);
        if (n < 0 || (size_t)n >= sizeof(buffer))
        {
            /* Fallback minimal redirect if snprintf fails/truncates */
            reply = "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: 0\r\n\r\n";
            offset = strlen(reply);
        }
        else
        {
            reply = buffer;
            offset = (size_t)n;
        }

        // Send the reply back to the client
        if (send(conn, reply, offset, 0) == -1)
        {
            perror("send");
            close(conn);
        }
    }
    else if (!knows_responsible_node(key))
    {
        fprintf(stderr, "Unknown responsible node for key %u, sending lookup\n", (unsigned)key);
        send_lookup(key, 0, SUCC_IP, SUCC_PORT);

        /* Inform client to retry later */
        reply = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n";
        offset = strlen(reply);

        // Send the reply back to the client
        if (send(conn, reply, offset, 0) == -1)
        {
            perror("send");
            close(conn);
        }
    }
    else
    {
        // if node responsible for key, process request
        if (strcmp(request->method, "GET") == 0)
        {
            // Find the resource with the given URI in the 'resources' array.
            size_t resource_length;
            const char *resource =
                get(request->uri, resources, MAX_RESOURCES, &resource_length);

            if (resource)
            {
                size_t payload_offset =
                    sprintf(reply, "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\n\r\n",
                            resource_length);
                memcpy(reply + payload_offset, resource, resource_length);
                offset = payload_offset + resource_length;
            }
            else
            {
                reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                offset = strlen(reply);
            }
        }
        else if (strcmp(request->method, "PUT") == 0)
        {
            // Try to set the requested resource with the given payload in the
            // 'resources' array.
            if (set(request->uri, request->payload, request->payload_length,
                    resources, MAX_RESOURCES))
            {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            }
            else
            {
                reply = "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
            }
            offset = strlen(reply);
        }
        else if (strcmp(request->method, "DELETE") == 0)
        {
            // Try to delete the requested resource from the 'resources' array
            if (delete(request->uri, resources, MAX_RESOURCES))
            {
                reply = "HTTP/1.1 204 No Content\r\n\r\n";
            }
            else
            {
                reply = "HTTP/1.1 404 Not Found\r\n\r\n";
            }
            offset = strlen(reply);
        }
        else
        {
            reply = "HTTP/1.1 501 Method Not Supported\r\n\r\n";
            offset = strlen(reply);
        }

        // Send the reply back to the client
        if (send(conn, reply, offset, 0) == -1)
        {
            perror("send");
            close(conn);
        }
    }
}

/**
 * Processes an incoming packet from the client.
 *
 * @param conn The socket descriptor representing the connection to the client.
 * @param buffer A pointer to the incoming packet's buffer.
 * @param n The size of the incoming packet.
 *
 * @return Returns the number of bytes processed from the packet.
 *         If the packet is successfully processed and a reply is sent, the
 * return value indicates the number of bytes processed. If the packet is
 * malformed or an error occurs during processing, the return value is -1.
 *
 */
ssize_t process_packet(int conn, char *buffer, size_t n)
{
    struct request request = {
        .method = NULL, .uri = NULL, .payload = NULL, .payload_length = -1};
    ssize_t bytes_processed = parse_request(buffer, n, &request);

    if (bytes_processed > 0)
    {
        send_reply(conn, &request);

        // Check the "Connection" header in the request to determine if the
        // connection should be kept alive or closed.
        const string connection_header = get_header(&request, "Connection");
        if (connection_header && strcmp(connection_header, "close"))
        {
            return -1;
        }
    }
    else if (bytes_processed == -1)
    {
        // If the request is malformed or an error occurs during processing,
        // send a 400 Bad Request response to the client.
        const string bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(conn, bad_request, strlen(bad_request), 0);
        printf("Received malformed request, terminating connection.\n");
        close(conn);
        return -1;
    }

    return bytes_processed;
}

/**
 * Sets up the connection state for a new socket connection.
 *
 * @param state A pointer to the connection_state structure to be initialized.
 * @param sock The socket descriptor representing the new connection.
 *
 */
static void connection_setup(struct connection_state *state, int sock)
{
    // Set the socket descriptor for the new connection in the connection_state
    // structure.
    state->sock = sock;

    // Set the 'end' pointer of the state to the beginning of the buffer.
    state->end = state->buffer;

    // Clear the buffer by filling it with zeros to avoid any stale data.
    memset(state->buffer, 0, HTTP_MAX_SIZE);
}

/**
 * Discards the front of a buffer
 *
 * @param buffer A pointer to the buffer to be modified.
 * @param discard The number of bytes to drop from the front of the buffer.
 * @param keep The number of bytes that should be kept after the discarded
 * bytes.
 *
 * @return Returns a pointer to the first unused byte in the buffer after the
 * discard.
 * @example buffer_discard(ABCDEF0000, 4, 2):
 *          ABCDEF0000 ->  EFCDEF0000 -> EF00000000, returns pointer to first 0.
 */
char *buffer_discard(char *buffer, size_t discard, size_t keep)
{
    memmove(buffer, buffer + discard, keep);
    memset(buffer + keep, 0, discard); // invalidate buffer
    return buffer + keep;
}

/**
 * Handles incoming connections and processes data received over the socket.
 *
 * @param state A pointer to the connection_state structure containing the
 * connection state.
 * @return Returns true if the connection and data processing were successful,
 * false otherwise. If an error occurs while receiving data from the socket, the
 * function exits the program.
 */
bool handle_connection(struct connection_state *state)
{
    // Calculate the pointer to the end of the buffer to avoid buffer overflow
    const char *buffer_end = state->buffer + HTTP_MAX_SIZE;

    // Check if an error occurred while receiving data from the socket
    ssize_t bytes_read =
        recv(state->sock, state->end, buffer_end - state->end, 0);
    if (bytes_read == -1)
    {
        perror("recv");
        close(state->sock);
        exit(EXIT_FAILURE);
    }
    else if (bytes_read == 0)
    {
        return false;
    }

    char *window_start = state->buffer;
    char *window_end = state->end + bytes_read;

    ssize_t bytes_processed = 0;
    while ((bytes_processed = process_packet(state->sock, window_start,
                                             window_end - window_start)) > 0)
    {
        window_start += bytes_processed;
    }

    if (bytes_processed == -1)
    {
        return false;
    }

    state->end = buffer_discard(state->buffer, window_start - state->buffer,
                                window_end - window_start);
    return true;
}

/**
 * Sets up a TCP server socket and binds it to the provided sockaddr_in address.
 *
 * @param addr The sockaddr_in structure representing the IP address and port of
 * the server.
 * @param socket_type The type of socket to create (e.g., SOCK_STREAM for TCP,
 * SOCK_DGRAM for UDP).
 *
 * @return The file descriptor of the created TCP server socket.
 */
static int setup_server_socket(struct sockaddr_in addr, int socket_type)
{
    const int enable = 1;
    const int backlog = 1;

    // Create a socket
    int sock = socket(AF_INET, socket_type, 0);
    if (sock == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    // int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Avoid dead lock on connections that are dropped after poll returns but
    // before accept is called
    if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
    {
        perror("fcntl");
        exit(EXIT_FAILURE);
    }

    // if (socket_type == SOCK_STREAM)
    //{ // TCP only because UDP
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) == -1)
    { // Set the SO_REUSEADDR socket option to allow reuse of local addresses
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    // }

    // Bind socket to the provided address
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Start listening on the socket with maximum backlog of 1 pending
    // connection
    if (socket_type != SOCK_STREAM)
    {
        return sock;
    }
    if (listen(sock, backlog))
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return sock;
}

/**
 *  The program expects 3; otherwise, it returns EXIT_FAILURE.
 *
 *  Call as:
 *
 *  ./build/webserver self.ip self.port
 */
int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4)
    {
        return EXIT_FAILURE;
    }
    /* Parse optional node id */
    if (argc == 4)
    {
        long id = strtol(argv[3], NULL, 10);
        if (id < 0 || id > 0xFFFF)
        {
            fprintf(stderr, "Node id out of range (0..65535)\n");
            return EXIT_FAILURE;
        }
        NODE_ID = (uint16_t)id;
    }
    else
    {
        NODE_ID = 0;
    }

    /* Read neighborhood from environment variables */
    const char *env;

    env = getenv("PRED_ID");
    if (env)
    {
        long id = strtol(env, NULL, 10);
        if (id >= 0 && id <= 0xFFFF)
        {
            PRED_ID = (uint16_t)id;
        }
        else
        {
            PRED_ID = NODE_ID;
        }
    }
    else
    {
        PRED_ID = NODE_ID;
    }

    env = getenv("PRED_IP");
    if (env)
    {
        strncpy(PRED_IP, env, sizeof(PRED_IP) - 1);
        PRED_IP[sizeof(PRED_IP) - 1] = '\0';
    }
    else
    {
        PRED_IP[0] = '\0';
    }

    env = getenv("PRED_PORT");
    if (env)
    {
        strncpy(PRED_PORT, env, sizeof(PRED_PORT) - 1);
        PRED_PORT[sizeof(PRED_PORT) - 1] = '\0';
    }
    else
    {
        PRED_PORT[0] = '\0';
    }

    env = getenv("SUCC_ID");
    if (env)
    {
        long id = strtol(env, NULL, 10);
        if (id >= 0 && id <= 0xFFFF)
        {
            SUCC_ID = (uint16_t)id;
        }
        else
        {
            SUCC_ID = NODE_ID;
        }
    }
    else
    {
        SUCC_ID = NODE_ID;
    }

    env = getenv("SUCC_IP");
    if (env)
    {
        strncpy(SUCC_IP, env, sizeof(SUCC_IP) - 1);
        SUCC_IP[sizeof(SUCC_IP) - 1] = '\0';
    }
    else
    {
        SUCC_IP[0] = '\0';
    }

    env = getenv("SUCC_PORT");
    if (env)
    {
        strncpy(SUCC_PORT, env, sizeof(SUCC_PORT) - 1);
        SUCC_PORT[sizeof(SUCC_PORT) - 1] = '\0';
    }
    else
    {
        SUCC_PORT[0] = '\0';
    }

    struct sockaddr_in addr = derive_sockaddr(argv[1], argv[2]);

    NODE_IP = ntohl(addr.sin_addr.s_addr);
    NODE_PORT = ntohs(addr.sin_port);

    int server_socket_TCP = setup_server_socket(addr, SOCK_STREAM);
    int server_socket_UDP = setup_server_socket(addr, SOCK_DGRAM); // Aufgabe 1.1 UDP socket

    fprintf(stderr, "Server listening on %s:%s (node id: %u)\n", argv[1], argv[2], (unsigned)NODE_ID);
    fprintf(stderr, "Predecessor: id=%u ip=%s port=%s\n", (unsigned)PRED_ID,
            PRED_IP[0] ? PRED_IP : "(unset)", PRED_PORT[0] ? PRED_PORT : "(unset)");
    fprintf(stderr, "Successor:   id=%u ip=%s port=%s\n", (unsigned)SUCC_ID,
            SUCC_IP[0] ? SUCC_IP : "(unset)", SUCC_PORT[0] ? SUCC_PORT : "(unset)");
    // Create an array of pollfd structures to monitor sockets.
    struct pollfd sockets[3] = {
        {.fd = server_socket_TCP, .events = POLLIN},
        {.fd = -1, .events = 0}, // temp acc tcp conn
        {.fd = server_socket_UDP, .events = POLLIN},
    };

    struct connection_state state = {0}; // Active TCP connection state
    while (true)
    {

        // Use poll() to wait for events on the monitored sockets.
        int ready = poll(sockets, sizeof(sockets) / sizeof(sockets[0]), -1);
        if (ready == -1)
        {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        // Process events on the monitored sockets.
        for (size_t i = 0; i < sizeof(sockets) / sizeof(sockets[0]); i += 1)
        {
            if (sockets[i].revents != POLLIN)
            {
                // If there are no POLLIN events on the socket, continue to the
                // next iteration.
                continue;
            }
            int s = sockets[i].fd;

            if (s == server_socket_UDP)
            {
                char buffer[HTTP_MAX_SIZE];

                ssize_t bytes_received = recvfrom(server_socket_UDP, buffer, HTTP_MAX_SIZE, 0, NULL, NULL);
                if (bytes_received == -1)
                {
                    perror("recvfrom");
                    close(server_socket_UDP);
                    exit(EXIT_FAILURE);
                }
                // if (bytes_received != sizeof(lookup_message_t))
                // {
                //     fprintf(stderr, "Received malformed UDP packet\n");
                //     continue;
                // }
                lookup_message_t *msg = (lookup_message_t *)buffer;
                fprintf(stderr, "Received UDP message type %u for hash id %u from node %u, ip: %u:%u\n",
                        (unsigned)msg->msg_type, (unsigned)ntohs(msg->hash_id),
                        (unsigned)ntohs(msg->node_id), (unsigned)ntohl(msg->ip), (unsigned)ntohs(msg->port));

                //Aufgabe 1.4 lookup reply und Aufgabe 1.5
                if (msg->msg_type == 0)
                {
                    uint16_t key = ntohs(msg->hash_id);
                    /*Im ersten Fall wird überprüft ob die Node selber oder  ihr Nachfolger verantworlich ist
                    Falls ja schicke direkt die Reply, falls nicht schicke lookup an Nachfolger (Fall 2)*/
                    if (is_responsible(key,NODE_ID,PRED_ID) || is_responsible(key,SUCC_ID,NODE_ID))
                    {
                        uint16_t reply_node_id = NODE_ID;
                        uint32_t reply_ip = NODE_IP;        //IP ist 4byte groß
                        uint16_t reply_port = NODE_PORT;

                        // If successor is responsible for this key, reply with successor's info

                        if (is_responsible(key,SUCC_ID,NODE_ID) &&(NODE_ID != SUCC_ID))   //Wenn der Nachfolger verantwortlich ist antworten mit dessen Werten
                        {
                            // Convert SUCC_IP string to numeric for the reply
                            struct in_addr addr;
                            inet_pton(AF_INET, SUCC_IP, &addr);
                            reply_node_id = SUCC_ID;
                            reply_ip = ntohl(addr.s_addr);
                            reply_port = (uint16_t)atoi(SUCC_PORT);
                        }
                        else {  //Sonst sind wir verantworlich
                            reply_node_id = htons(NODE_ID);
                            reply_ip = htons(NODE_IP);
                            reply_port = htons(NODE_PORT);
                        }
                        //Reply_msg vorbereiten
                        lookup_message_t reply_msg = {
                            .msg_type = 1,
                            .hash_id = htons(NODE_ID), 
                            .node_id = htons(reply_node_id),
                            .ip = htonl(reply_ip),
                            .port = htons(reply_port),
                        };
                        // Convert sender's IP and port to strings for reply
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &msg->ip, ip_str, sizeof(ip_str));
                        char port_str[6];
                        snprintf(port_str, sizeof(port_str), "%u", ntohs(msg->port));
                        send_udp_message(&reply_msg, ip_str, port_str);
                    }
                    //Fall 2 weder Node Selber noch Nachfolger ist verantwortlich -> Lookup an Nachfolger weiterleiten
                    else{
                        fprintf(stderr, "Forwarding lookup for key %u to successor %s:%s\n", key, SUCC_IP, SUCC_PORT);
                        send_udp_message(msg,SUCC_IP,SUCC_PORT);
                    }
                }
            }
            else if (s == server_socket_TCP)
            {

                // If the event is on the server_socket, accept a new connection
                // from a client.
                int connection = accept(server_socket_TCP, NULL, NULL);
                if (connection == -1 && errno != EAGAIN &&
                    errno != EWOULDBLOCK)
                {
                    close(server_socket_TCP);
                    perror("accept");
                    exit(EXIT_FAILURE);
                }
                else
                {
                    connection_setup(&state, connection);

                    // limit to one connection at a time
                    sockets[0].events = 0;
                    sockets[1].fd = connection;
                    sockets[1].events = POLLIN;
                }
            }
            else
            {
                assert(s == state.sock);

                // Call the 'handle_connection' function to process the incoming
                // data on the socket.
                bool cont = handle_connection(&state);
                if (!cont)
                { // get ready for a new connection
                    sockets[0].events = POLLIN;
                    sockets[1].fd = -1;
                    sockets[1].events = 0;
                }
            }
        }
    }
    return EXIT_SUCCESS;
}
