#include<iostream>
#include<cstring>
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>
#include <thread>
#include <vector>



#define SPORT 12345
#define SSPORT 1234
#define USPORT 12346
#define buffer_size 1024


using namespace std;

#include<openssl/ssl.h>
#include<iostream>

using namespace std;

SSL_CTX *ctx;
SSL *ssl;
BIO *bio;

bool *client_stop;

class IOClient {
    private:
    SSL *ssl;
    string name;
    public:
    bool *client_stop;
    IOClient(SSL* ssl, string name, bool *temp_stop) {
        // constructor
        this->ssl = ssl;
        this->name = name;
        this->client_stop = temp_stop;
    }
    // function to contineously read from the socket
    void read_from_socket(vector<string> & victim2msgs) {
        char buffer[1024];
        int recv_len;
        while (!*this->client_stop) {
            fd_set read_fds;
            struct timeval timeout;
            int result;

            // Clear the read file descriptor set
            FD_ZERO(&read_fds);

            // Add the SSL socket file descriptor to the read file descriptor set
            FD_SET(SSL_get_fd(ssl), &read_fds);

            // Set the timeout value to 10 seconds
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            // Wait for input for a maximum of 10 seconds
            result = select(SSL_get_fd(ssl) + 1, &read_fds, NULL, NULL, &timeout);
            if (result == -1) {
                perror("select");
                return;
            } else if (result == 0) {
                continue; // Continue the loop to check for stop condition
            }
            try {
                recv_len = SSL_read(ssl, buffer, 1024);
            } catch (exception e) {
                continue;
            }
            if(strcmp(buffer,"") == 0 || strcmp(buffer, "chat_close") == 0){
                *this->client_stop = true;
                continue;
            }
            buffer[recv_len] = '\0';
            if(strcmp(buffer, "chat_hello_secure") == 0){
                cout<<"Received chat_hello_secure again"<<endl;
                char *msg2 = (char*)"chat_hello_secure_ack\0";
                if (SSL_write(ssl, msg2, strlen(msg2)) <= 0) {
                    ERR_print_errors_fp(stderr);
                }
            }
            cout << "\n" << name << " >> " << buffer << endl;
            victim2msgs.push_back(buffer);
        }
    }
    // function to contineously write to the socket
    void write_to_socket(vector<string> & victim1msgs) {
        char buffer[1024];
        while (!*this->client_stop) {

            while(victim1msgs.size() > 0){
                strcpy(buffer, victim1msgs[0].c_str());
                victim1msgs.erase(victim1msgs.begin());
                // take input to as modify or not message
                cout<<"Do you want to modify the message?"<<buffer<<" (yes/no)"<<endl;
                char modify[10];
                cin.getline(modify, 10);

                if (strcmp(modify, "yes") == 0) {
                    cout<<"Enter the modified message"<<endl;
                    // erase buffer 
                    memset(buffer, 0, 1024);
                    cin.getline(buffer, 1024);
                    cout<<"Modified message is "<<buffer<<endl;
                }
                

                if (SSL_write(ssl, buffer, strlen(buffer)) < 0) {
                    perror("SSL_write");
                    return;
                }
                if (strcmp(buffer, "chat_close") == 0) {
                    // send a message to the client
                    *this->client_stop = true;
                    break;
                }
            }
        }
    }
};



class Client {
    private:
    int client_fd;
    struct sockaddr_in server_addr, client_addr;
    bool *unsec_stop;
    string your_name;

    public: Client (char *server_ip, string your_name) {
        this->your_name = your_name;
        if ((client_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("client socket failed");
            return;
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SPORT);
        server_addr.sin_addr.s_addr = inet_addr(server_ip);
        cout<<"In Trudy Bob ip address is "<<server_ip<<endl;

    }
    
    // send the message to the server
    int initiate_handshake() {
        socklen_t server_addr_len = sizeof(server_addr);
        char buffer[buffer_size];
        
        // set buffer to null
        buffer[0] = '\0';
        while(strcmp(buffer, "chat_ok_reply") != 0) {
            char *msg = (char*)"chat_hello\0";
            sendto(client_fd, msg, strlen(msg), 0, (struct sockaddr *)&server_addr, server_addr_len);
            cout<<"Sent chat_hello to Bob"<<endl;

            fd_set read_fds;
            struct timeval timeout;
            int result;

            // Clear the read file descriptor set
            FD_ZERO(&read_fds);

            // Add the client socket file descriptor to the read file descriptor set
            FD_SET(client_fd, &read_fds);

            // Set the timeout value to 10 seconds
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            // Wait for input for a maximum of 10 seconds
            result = select(client_fd + 1, &read_fds, NULL, NULL, &timeout);
            if (result == -1) {
                perror("select");
            } else if (result == 0) {
                cout << "No input received within 10 seconds." << endl;
                continue; // Continue the loop to check for stop condition
            }
            // Now, receive the message from the server
            int recv_len;
            if ((recv_len = recvfrom(client_fd, buffer, buffer_size, 0, (struct sockaddr *)&server_addr, &server_addr_len)) < 0) {
                perror("recvfrom had an error");
                // return;
            }
            // print the ip address:port and the message
            buffer[recv_len] = '\0';
            cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;
            FD_ZERO(&read_fds);
        }
        return 1;
    }

    void unSecRead (int fd, sockaddr_in server_addr2) {
        socklen_t server_addr_len = sizeof(server_addr);
        char buffer[buffer_size];
        int recv_len;
        while (!*this->unsec_stop) {
            fd_set read_fds;
            struct timeval timeout;
            int result;

            // Clear the read file descriptor set
            FD_ZERO(&read_fds);

            // Add the SSL socket file descriptor to the read file descriptor set
            FD_SET(fd, &read_fds);

            // Set the timeout value to 10 seconds
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            // Wait for input for a maximum of 10 seconds
            result = select(fd + 1, &read_fds, NULL, NULL, &timeout);
            if (result == -1) {
                perror("select");
                return;
            } else if (result == 0) {
                continue; // Continue the loop to check for stop condition
            }
            if ((recv_len = recvfrom(fd, buffer, buffer_size, 0, (struct sockaddr *)&server_addr2, &server_addr_len)) < 0) {
                perror("recvfrom had an error");
                return;
            }
            buffer[recv_len] = '\0';
            cout << "Bob" << " >> " << buffer << endl;
            if(strcmp(buffer,"") == 0 || strcmp(buffer, "chat_close") == 0){
                *this->unsec_stop = true;
                continue;
            }
            memset(buffer, 0, buffer_size);
        }
        cout<<"Unsecure Read thread closed"<<endl;
    }

    void unSecWrite (int fd, sockaddr_in server_addr2) {
        char buffer[buffer_size];
        socklen_t server_addr_len = sizeof(server_addr);
        sendto(client_fd, (char*)"ACK\0", strlen("ACK\0"), 0, (struct sockaddr *)&server_addr, server_addr_len);
        while (!*this->unsec_stop) {
            cin.getline(buffer, buffer_size);
            sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr *)&server_addr2, sizeof(server_addr2));
            if (strcmp(buffer, "chat_close") == 0) {
                *this->unsec_stop = true;
                break;
            }
            memset(buffer, 0, buffer_size);
        }
        cout<<"Unsecure Write thread closed"<<endl;
    }

    void makeUnsecureChat() {
        this->unsec_stop = new bool(false);
        struct sockaddr_in server_addr2, client_addr2;
        server_addr2.sin_family = AF_INET;
        server_addr2.sin_port = htons(USPORT);
        server_addr2.sin_addr.s_addr = inet_addr(inet_ntoa(server_addr.sin_addr));
        
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("socket fd");
            return;
        }
        client_addr2.sin_family = AF_INET;
        client_addr2.sin_port = htons(USPORT);
        client_addr2.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *)&client_addr2, sizeof(client_addr2)) < 0) {
            perror("bind fd");
            return;
        }
        thread read_thread(&Client::unSecRead, this, fd, server_addr2);
        thread write_thread(&Client::unSecWrite, this, fd, server_addr2);
        read_thread.join();
        write_thread.join();
    }

    void initiate_secure_handshake(vector<string> & victim1msgs1, vector<string> & victim2msgs1) {

        socklen_t server_addr_len = sizeof(server_addr);
        char buffer[buffer_size];
        // set buffer to null
        buffer[0] = '\0';
        int recv_len;
        while((strcmp(buffer, "chat_START_SSL_ACK") != 0)) {
            // send an initial message to the server
            char *msg = (char*)"chat_START_SSL\0";
            sendto(client_fd, msg, strlen(msg), 0, (struct sockaddr *)&server_addr, server_addr_len);
            //receive the message from the server
            
            fd_set read_fds;
            struct timeval timeout;
            int result;

            // Clear the read file descriptor set
            FD_ZERO(&read_fds);

            // Add the client socket file descriptor to the read file descriptor set
            FD_SET(client_fd, &read_fds);

            // Set the timeout value to 10 seconds
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            // Wait for input for a maximum of 10 seconds
            result = select(client_fd + 1, &read_fds, NULL, NULL, &timeout);
            if (result == -1) {
                perror("select");
                // return;
            } else if (result == 0) {
                cout << "No input received within 10 seconds." << endl;
                continue; // Continue the loop to check for stop condition
            }

            // Now, receive the message from the server
            int recv_len;
            if ((recv_len = recvfrom(client_fd, buffer, buffer_size, 0, (struct sockaddr *)&server_addr, &server_addr_len)) < 0) {
                perror("recvfrom had an error");
                // return;
            }
            // print the ip address:port and the message
            buffer[recv_len] = '\0';
            cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;
            if(strcmp(buffer, "chat_START_SSL_NOT_SUPPORTED") == 0) {
                cout << "\nBob does not have capability to set up secure chat.......\n\n";
                makeUnsecureChat();
                return;
            }
            FD_ZERO(&read_fds);
        }
        // sending unreliable ACK
        sendto(client_fd, (char*)"ACK\0", strlen("ACK\0"), 0, (struct sockaddr *)&server_addr, server_addr_len);
        
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        struct sockaddr_in this_addr, new_addr;
        this_addr.sin_family = AF_INET;
        this_addr.sin_port = htons(12346);
        this_addr.sin_addr.s_addr = INADDR_ANY;

        new_addr.sin_family = AF_INET;
        new_addr.sin_port = htons(SSPORT);
        new_addr.sin_addr.s_addr = inet_addr(inet_ntoa(server_addr.sin_addr));
        
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            perror("socket fd");
            return;
        }
        if (bind(fd, (struct sockaddr *)&this_addr, sizeof(this_addr)) < 0) {
            perror("bind fd");
            return;
        }

        ctx = SSL_CTX_new(DTLS_client_method());
        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }

        string crt_name_str;
        if (strcmp(your_name.c_str(), "Alice") == 0) {
            crt_name_str = (char*)"fakealice.crt";
        } else {
            crt_name_str = (char*)"fakebob.crt";
        }
        char * crt_name = (char*)crt_name_str.c_str();

        string key_name_str;
        if (strcmp(your_name.c_str(), "Alice") == 0) {
            key_name_str = (char*)"fakealice.pem";
        } else {
            key_name_str = (char*)"fakebob.pem";
        }

        char * key_name = (char*)key_name_str.c_str();

        cout << "Using certificate: " << crt_name << endl;
        cout << "Using key: " << key_name << endl;

        // also add the certificate
        if (SSL_CTX_use_certificate_file(ctx, crt_name, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, key_name, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return;
        }
        if (!SSL_CTX_check_private_key(ctx)) {
            ERR_print_errors_fp(stderr);
            return;
        }
        SSL_CTX_set_verify_depth(ctx, 2);
        SSL_CTX_set_read_ahead(ctx, 1);

        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }

        bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        if (bio == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }
        if (connect(fd, (struct sockaddr *)&new_addr, sizeof(new_addr)) < 0) {
            perror("connect");
            return;
        }
        cout << "UDP connection established" << endl;

        struct sockaddr_storage ss;
        
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ss);
        recv_len = SSL_read(ssl, buffer, 1024);
        SSL_set_bio(ssl, bio, bio);
        while(SSL_connect(ssl) <= 0) {
            perror("SSL_connect");
            ERR_print_errors_fp(stderr);
            sendto(client_fd, (char*)"ACK\0", strlen("ACK\0"), 0, (struct sockaddr *)&server_addr, server_addr_len);
        }
        cout<<"SSL connection successful"<<endl;
        struct timeval timeout;
        timeout.tv_sec = 500;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        
        cout << "Connected to the server" << endl;

        memset(buffer, 0, buffer_size);
        recv_len = 0;
        
        if ((recv_len = SSL_read(ssl, buffer, buffer_size)) < 0) {
            ERR_print_errors_fp(stderr);
            return;
        }
        buffer[recv_len] = '\0';
        cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;

        
        // send a message to the server
        char *msg2 = (char*)"chat_hello_secure_ack\0";
        if (SSL_write(ssl, msg2, strlen(msg2)) <= 0) {
            ERR_print_errors_fp(stderr);
            return;
        }

        cout << endl;

        client_stop = new bool(false);

        // create an IO object
        IOClient io = IOClient(ssl, your_name,client_stop);
        // create a thread to read from the socket
        thread read_thread(&IOClient::read_from_socket, io,ref(victim2msgs1));
        // create a thread to write to the socket
        thread write_thread(&IOClient::write_to_socket, io, ref(victim1msgs1));
        
        read_thread.join();
        *io.client_stop = true;
        write_thread.join();
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);

        cout<<"Connection closed Successfully"<<endl;
    }

};
