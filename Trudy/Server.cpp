#include<iostream>
#include<cstring>
#include<openssl/ssl.h>
#include<openssl/err.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>
#include <vector>

#include <thread>

#define SPORT 12345
#define SSPORT 1234
#define USPORT 12346
#define buffer_size 1024


using namespace std;

#include<openssl/ssl.h>
#include<iostream>

using namespace std;

bool *server_stop;
bool secure = true;
bool *unsecure_stop;

class IOServer {
    private:
    SSL *ssl;
    string name;
    public:
    bool *server_stop;
    bool *unsecure_stop;
    IOServer(SSL* ssl, string name, bool *temp_stop) {
        // constructor
        this->ssl = ssl;
        this->name = name;
        this->server_stop = temp_stop;
        this->unsecure_stop = temp_stop;
    }
    
    // function to contineously read from the socket
    void read_from_socket(vector<string> & victim1msgs) {
        
        char buffer[1024];
        int recv_len;
        while (!*this->server_stop) {
            try {
                recv_len = SSL_read(ssl, buffer, 1024);
            } catch (exception e) {
                continue;
            }
            buffer[recv_len] = '\0';
            if(strcmp(buffer,"") == 0){
                *this->server_stop = true;
                continue;
            }
            cout << "\n" << name << " >> " << buffer << endl;
            victim1msgs.push_back(buffer);
            if (strcmp(buffer,"") == 0 || strcmp(buffer, "chat_close") == 0) {
                // send a message to the client
                *this->server_stop = true;
                break;
            }
        }
    }
    
    void write_to_socket(vector<string> & victim2msgs) {
        char buffer[1024];
        while (!*this->server_stop) {
            
            while(victim2msgs.size() > 0){
                strcpy(buffer, victim2msgs[0].c_str());
                victim2msgs.erase(victim2msgs.begin());

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
                    *this->server_stop = true;
                    break;
                }
            }
        }
    }
};

static int generate_cookie (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;
    buffer = (unsigned char *)OPENSSL_malloc(1024);
    if (buffer == NULL) {
        printf("OPENSSL_malloc failed\n");
        return 0;
    }
    if (!SSL_get_server_random(ssl, buffer, 32)) {
        printf("SSL_get_server_random failed\n");
        return 0;
    }
    if (!SSL_get_client_random(ssl, buffer + 32, 32)) {
        printf("SSL_get_client_random failed\n");
        return 0;
    }
    
    length = 64 + 32;
    if (!EVP_Digest(buffer, length, result, &resultlength, EVP_sha1(), NULL)) {
        printf("EVP_Digest failed\n");
        return 0;
    }
    memcpy(cookie, result, 16);
    *cookie_len = 16;
    OPENSSL_free(buffer);
    return 1;
}

static int verify_cookie (SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    // verify the cookie
    return 1;
}


class Server {
    private: int server_fd, unsecure_fd;
    struct sockaddr_in server_addr, client_addr;
    struct sockaddr_in unsecure_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char buffer[buffer_size];
    int recv_len;
    bool *unsec_stop = new bool(false);
    bool listenerStop = false;
    string server_name;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;

    struct sockaddr_in new_addr;
    socklen_t new_addr_len = sizeof(new_addr);
    int fd;
    int client_fd;
    
    public: Server(string server_name) {
        this->server_name = server_name;
        if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("socket");
            return;
        }
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(SPORT);
        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("bind");
            return;
        }
        cout << "Server is running on IP " << inet_ntoa(server_addr.sin_addr) << endl;
        cout << "Server is running on port " << SPORT << endl;

    }

    // return a socket file descriptor
    int create_socket() {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("socket");
            return -1;
        }
        struct sockaddr_in server_addr2;
        server_addr2.sin_family = AF_INET;
        server_addr2.sin_port = htons(SSPORT);
        server_addr2.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *)&server_addr2, sizeof(server_addr2)) < 0) {
            perror("bind");
            return -1;
        }
        if (listen(fd, 1) < 0) {
            perror("listen");
            return -1;
        }
        return fd;
        
    }

    void listen_to_messages(vector<string> & victim1msgs, vector<string> & victim2msgs) {
            secure = true;

            cout<<"Listening for new Connections on port"<<endl;
            if ((recv_len = recvfrom(server_fd, buffer, buffer_size, 0, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
                perror("recvfrom");
                return;
            }
            buffer[recv_len] = '\0';
            socklen_t server_addr_len = sizeof(server_addr);
            cout << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << " >> " << buffer << endl;
            
            while(strcmp(buffer, "chat_START_SSL") != 0) {
                char *msg = (char*)"chat_ok_reply\0";
                sendto(server_fd, msg, strlen(msg), 0, (struct sockaddr *)&client_addr, client_addr_len);
                cout<<"Sent chat_ok_reply on port:"<<endl;

                fd_set read_fds;
                struct timeval timeout;
                int result;

                // Clear the read file descriptor set
                FD_ZERO(&read_fds);

                // Add the client socket file descriptor to the read file descriptor set
                FD_SET(server_fd, &read_fds);

                // Set the timeout value to 10 seconds
                timeout.tv_sec = 10;
                timeout.tv_usec = 0;

                // Wait for input for a maximum of 10 seconds
                result = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
                if (result == -1) {
                    perror("select");
                } else if (result == 0) {
                    cout << "No input received within 10 seconds." << endl;
                    continue; // Continue the loop to check for stop condition
                }

                // Now, receive the message from the server
                int recv_len;
                if ((recv_len = recvfrom(server_fd, buffer, buffer_size, 0, (struct sockaddr *)&server_addr, &server_addr_len)) < 0) {
                    perror("recvfrom had an error");
                }
                buffer[recv_len] = '\0';
                cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;
                FD_ZERO(&read_fds);
            }
            while(strcmp(buffer, "ACK") != 0) {
                char *msg = (char*)"chat_START_SSL_ACK\0";
                sendto(server_fd, msg, strlen(msg), 0, (struct sockaddr *)&client_addr, client_addr_len);
                cout<<"Sent chat_START_SSL_ACK"<<endl;

                fd_set read_fds;
                struct timeval timeout;
                int result;

                // Clear the read file descriptor set
                FD_ZERO(&read_fds);

                // Add the client socket file descriptor to the read file descriptor set
                FD_SET(server_fd, &read_fds);

                // Set the timeout value to 10 seconds
                timeout.tv_sec = 10;
                timeout.tv_usec = 0;

                // Wait for input for a maximum of 10 seconds
                result = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
                if (result == -1) {
                    perror("select");
                } else if (result == 0) {
                    cout << "No input received within 10 seconds." << endl;
                    continue; // Continue the loop to check for stop condition
                }

                // Now, receive the message from the server
                int recv_len;
                if ((recv_len = recvfrom(server_fd, buffer, buffer_size, 0, (struct sockaddr *)&server_addr, &server_addr_len)) < 0) {
                    perror("recvfrom had an error");
                }
                // print the ip address:port and the message
                buffer[recv_len] = '\0';
                cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;
                FD_ZERO(&read_fds);
            }

            setup_dtls();
            *this->unsec_stop = false;
            thread secure_thread(&Server::make_secure_handshake, this, ref(victim1msgs), ref(victim2msgs));
            secure_thread.detach();
    }

    void setup_dtls() {
        
        cout<<"Setting up DTLS"<<endl;
        // DTLS setup has not been done, set it up
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        this->ctx = SSL_CTX_new(DTLS_server_method());
        if (this->ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }
        
        typedef int (*new_session_cb)(SSL *ssl, SSL_SESSION *sess);
        typedef SSL_SESSION *(*get_session_cb)(SSL *ssl, const struct ssl_session_st *sess);

        this->new_addr.sin_family = AF_INET;
        this->new_addr.sin_port = htons(SSPORT);
        this->new_addr.sin_addr.s_addr = INADDR_ANY;

        this->fd = socket(this->new_addr.sin_family, SOCK_DGRAM, 0);
        if (this->fd < 0) {
            perror("socket fd");
            return;
        }

        if (bind(this->fd, (struct sockaddr *)&this->new_addr, sizeof(this->new_addr)) < 0) {
            perror("bind fd");
            return;
        }

        string crt_name_str;
        if (strcmp(server_name.c_str(), "Alice") == 0) {
            crt_name_str = "fakealice.crt";
        } else {
            crt_name_str = "fakebob.crt";
        }

        char * crt_name = (char *)crt_name_str.c_str();

        string key_name_str;
        if (strcmp(server_name.c_str(), "Alice") == 0) {
            key_name_str = "fakealice.pem";
        } else {
            key_name_str = "fakebob.pem";
        }

        char * key_name = (char *)key_name_str.c_str();

        cout << "Using certificate: " << crt_name << endl;
        cout << "Using key: " << key_name << endl;


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

        SSL_CTX_set_verify(this->ctx, SSL_VERIFY_PEER, verify_peer);
        SSL_CTX_set_read_ahead(this->ctx, 1);
        SSL_CTX_set_cookie_generate_cb(this->ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(this->ctx, verify_cookie);
        cout<<"Certificate verification succeeded"<<endl;

        this->bio = BIO_new_dgram(this->fd, BIO_NOCLOSE);
        if (this->bio == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }
        this->timeout.tv_sec = 5;
        this->timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &this->timeout);
        this->ssl = SSL_new(this->ctx);
        if (this->ssl == NULL) {
            ERR_print_errors_fp(stderr);
            return;
        }
        
        SSL_set_bio(this->ssl, this->bio, this->bio);

    }

    static int verify_peer(int verify_ok, X509_STORE_CTX *ctx) {
        return 1;
    }

    void unSecRead () {
        socklen_t server_addr_len = sizeof(unsecure_addr);
        char buffer[buffer_size];
        int recv_len;
        while (!*this->unsec_stop) {
             if ((recv_len = recvfrom(unsecure_fd, buffer, buffer_size, 0, (struct sockaddr *)&unsecure_addr, &server_addr_len)) < 0) {
                perror("recvfrom");
                return;
            }
            buffer[recv_len] = '\0';
            cout << "Alice" << " >> " << buffer << endl;
            if (strcmp(buffer, "chat_close") == 0) {
                *this->unsec_stop = true;
                break;
            }
            memset(buffer, 0, buffer_size);
        }
    }

    void unSecWrite (sockaddr_in client_addr2) {
        char buffer[buffer_size];
        while (!*this->unsec_stop) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);

            struct timeval timeout;
            timeout.tv_sec = 10; // Timeout set to 10 seconds
            timeout.tv_usec = 0;

            int ready = select(STDIN_FILENO + 1, &fds, NULL, NULL, &timeout);

            if (ready == -1) {
                perror("select");
                return;
            } else if (ready == 0) {
                continue; // Continue the loop to check for stop condition
            }
            cin.getline(buffer, buffer_size);
            sendto(unsecure_fd, buffer, strlen(buffer), 0, (struct sockaddr *)&client_addr2, client_addr_len);
            if (strcmp(buffer, "chat_close") == 0) {
                *this->unsec_stop = true;
                break;
            }
            memset(buffer, 0, buffer_size);
        }
    }

    void make_secure_handshake(vector<string> & victim1msgs, vector<string> & victim2msgs) {

        while(DTLSv1_listen(this->ssl, (BIO_ADDR *)&this->client_addr) <= 0) {
            cout<<"Secure chat not possible"<<endl;
            ERR_print_errors_fp(stderr);
            secure = false;
            close(this->fd);
            // makeUnSecureChat();
            return;
        }

        close(this->fd);
        //handle connection
        this->client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (this->client_fd < 0) {
            perror("socket client_fd");
            return;
        }
        if (bind(this->client_fd, (struct sockaddr *)&this->new_addr, sizeof(this->server_addr)) < 0) {
            perror("bind client_fd");
            return;
        }

        if (connect(this->client_fd, (struct sockaddr *)&this->client_addr, sizeof(this->client_addr)) < 0) {
            perror("connect");
            return;
        }

        struct sockaddr_storage ss;

        BIO_set_fd(SSL_get_rbio(this->ssl), this->client_fd, BIO_NOCLOSE);
        BIO_ctrl(SSL_get_rbio(this->ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &ss);
        struct timeval timeout2;
        timeout2.tv_sec = 500;
        timeout2.tv_usec = 0;
        BIO_ctrl(SSL_get_rbio(this->ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout2);
        
        if (SSL_accept(this->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return;
        }

        cout << "Server accepted the secure connection" << endl;
        
        char buffer[1024];
        memset(buffer, 0, 1024);
        while(strcmp(buffer, "chat_hello_secure_ack") != 0) {
            char *msg = (char*)"chat_hello_secure\0";
            SSL_write(this->ssl, msg, strlen(msg));
            cout<<"Sent chat_hello_secure"<<endl;

            fd_set read_fds;
            struct timeval timeout;
            int result;

            // Clear the read file descriptor set
            FD_ZERO(&read_fds);

            // Add the client socket file descriptor to the read file descriptor set
            FD_SET(SSL_get_fd(ssl), &read_fds);

            // Set the timeout value to 10 seconds
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            // Wait for input for a maximum of 10 seconds
            result = select(SSL_get_fd(ssl) + 1, &read_fds, NULL, NULL, &timeout);
            if (result == -1) {
                perror("select");
            } else if (result == 0) {
                cout << "No input received within 10 seconds." << endl;
                continue; // Continue the loop to check for stop condition
            }

            try {
                recv_len = SSL_read(ssl, buffer, 1024);
            } catch (exception e) {
                continue;
            }
            
            cout << inet_ntoa(server_addr.sin_addr) << ":" << ntohs(server_addr.sin_port) << " >> " << buffer << endl;
            
        }

        server_stop = new bool(false);
        // create an IO object
        IOServer io = IOServer(this->ssl, server_name, server_stop);
        // create a thread to read from the socket
        thread read_thread(&IOServer::read_from_socket, io,ref(victim1msgs));
        // create a thread to write to the socket
        thread write_thread(&IOServer::write_to_socket, io,ref(victim2msgs));
        
        read_thread.join();
        *io.server_stop = true;
        write_thread.join();
        close(this->client_fd);
    }
};