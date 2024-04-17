#include "Server.cpp"
#include "Client.cpp"
#include<iostream>

#include <netdb.h>
// #include <arpa/inet.h>

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


// create a function to initiate the secure handshake

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " [-s] [-c <IP address/Hostname>]" << endl;
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        char * client_name = (char *)"alice1\0";
        char * client_ip = get_ip_address(client_name);
        // cout<<client_ip<<endl;

        Server server = Server(client_ip);
        server.listen_to_messages();
        server.make_secure_handshake();

    } else if (strcmp(argv[1], "-c") == 0) {
        char * server_name = argv[2];
        char * server_ip;
        // get the ip address of the server from the hostname
        server_ip = get_ip_address(server_name);
        Client client = Client(server_ip);     

        if (client.initiate_handshake()){
            client.initiate_secure_handshake();
        }


    } else {
        cout << "Usage: " << argv[0] << " [-s] [-c <IP address/Hostname>]" << endl;
        return 1;
    }
}