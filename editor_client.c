#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 8192

SOCKET client_socket;
int user_id = -1;

DWORD WINAPI receive_messages(LPVOID arg) {
    char buffer[BUFFER_SIZE];
    while (1) {
        int bytes = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            printf("Disconnected from server\n");
            exit(1);
        }
        buffer[bytes] = '\0';
        printf("\n[Server] %s\n> ", buffer);
        fflush(stdout);
    }
    return 0;
}

int main() {
    WSADATA wsaData;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    HANDLE recv_thread;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Connect to server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection failed: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Connected to collaborative editor\n");
    
    // Authentication
    char username[50], password[50];
    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;
    
    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
    sprintf(buffer, "USER:%s", username);
    send(client_socket, buffer, strlen(buffer), 0);
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    sprintf(buffer, "PASS:%s", password);
    send(client_socket, buffer, strlen(buffer), 0);
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    printf("Authentication: %s\n", buffer);
    
    if (strstr(buffer, "ERROR")) {
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // Start message receiving thread
    recv_thread = CreateThread(NULL, 0, receive_messages, NULL, 0, NULL);
    
    // Main input loop
    while (1) {
        printf("\nOptions:\n");
        printf("1. Insert text\n");
        printf("2. Delete text\n");
        printf("3. Request lock\n");
        printf("4. Release lock\n");
        printf("5. Show document\n");
        printf("6. Exit\n");
        printf("Choice: ");
        
        int choice;
        scanf("%d", &choice);
        getchar(); // Consume newline
        
        switch (choice) {
            case 1: {
                int pos;
                char text[100];
                printf("Position: ");
                scanf("%d", &pos);
                getchar();
                printf("Text: ");
                fgets(text, sizeof(text), stdin);
                text[strcspn(text, "\n")] = 0;
                
                sprintf(buffer, "INSERT:%d:%s", pos, text);
                break;
            }
            case 2: {
                int pos, len;
                printf("Position: ");
                scanf("%d", &pos);
                printf("Length: ");
                scanf("%d", &len);
                
                sprintf(buffer, "DELETE:%d:%d", pos, len);
                break;
            }
            case 3:
                strcpy(buffer, "LOCK:");
                break;
            case 4:
                strcpy(buffer, "UNLOCK:");
                break;
            case 5:
                strcpy(buffer, "SYNC:");
                break;
            case 6:
                closesocket(client_socket);
                WSACleanup();
                exit(0);
            default:
                printf("Invalid choice\n");
                continue;
        }
        
        send(client_socket, buffer, strlen(buffer), 0);
        Sleep(100); // Small delay
    }
    
    closesocket(client_socket);
    WSACleanup();
    return 0;
}