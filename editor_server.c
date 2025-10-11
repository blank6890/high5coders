#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_USERS 20
#define MAX_DOCUMENT_SIZE 500000
#define MAX_USERNAME 50
#define PORT 8080
#define LOCK_TIMEOUT 30
#define MAX_CHAT_MESSAGES 1000

// User structure
typedef struct {
    int id;
    char username[MAX_USERNAME];
    SOCKET socket;
    int active;
    int cursor_position;
    time_t last_activity;
    char color[8];
    int is_ai;
} User;

// Chat message structure for GUI support
typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char message[1000];
    time_t timestamp;
    int is_ai;
} ChatMessage;

// User database with hashed passwords
typedef struct {
    char username[MAX_USERNAME];
    char password_hash[65];
    int user_id;
} UserAccount;

// Document structure
typedef struct {
    char content[MAX_DOCUMENT_SIZE];
    int length;
    CRITICAL_SECTION lock;
    User* locked_by;
    time_t lock_time;
    ChatMessage chat_messages[MAX_CHAT_MESSAGES];
    int chat_count;
} Document;

// Global variables
User users[MAX_USERS];
UserAccount user_database[100];
int user_db_count = 0;
Document document;
SOCKET server_socket;
int user_count = 0;
CRITICAL_SECTION users_mutex;

// Color codes for different users
const char* user_colors[] = {
    "#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", 
    "#FECA57", "#FF9FF3", "#54A0FF", "#5F27CD"
};

// ========== FUNCTION DECLARATIONS ==========
int hash_password(const char* password, char* output_hash);
void send_error(SOCKET client_socket, const char* error);
void send_success(SOCKET client_socket, const char* message);
int authenticate_user(SOCKET client_socket);
void send_document_state(SOCKET client_socket);
void send_user_list(SOCKET client_socket);
void send_chat_history(SOCKET client_socket);
void process_client_message(SOCKET client_socket, char* message);
void broadcast_chat_message(const ChatMessage* msg);
unsigned __stdcall handle_client(void* arg);
unsigned __stdcall broadcast_updates(void* arg);
unsigned __stdcall check_locks(void* arg);
void initialize_document();
// ========== END FUNCTION DECLARATIONS ==========

// 1. Password hashing using Windows Crypto API
int hash_password(const char* password, char* output_hash) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // SHA256 produces 32 bytes
    DWORD hashLen = 32;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    
    if (!CryptHashData(hHash, (BYTE*)password, (DWORD)strlen(password), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return 0;
    }
    
    // Convert binary hash to hex string
    for (DWORD i = 0; i < hashLen; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[64] = '\0';
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return 1;
}

// 5. send_error function
void send_error(SOCKET client_socket, const char* error) {
    char error_msg[256];
    int len = snprintf(error_msg, sizeof(error_msg), "ERROR:%s", error);
    if (len > 0) {
        if (send(client_socket, error_msg, len, 0) == SOCKET_ERROR) {
            printf("Failed to send error message: %d\n", WSAGetLastError());
        } else {
            printf("Sent error: %s\n", error);
        }
    }
}

// 6. send_success function
void send_success(SOCKET client_socket, const char* message) {
    char success_msg[256];
    int len = snprintf(success_msg, sizeof(success_msg), "SUCCESS:%s", message);
    if (len > 0) {
        if (send(client_socket, success_msg, len, 0) == SOCKET_ERROR) {
            printf("Failed to send success message: %d\n", WSAGetLastError());
        } else {
            printf("Sent success: %s\n", message);
        }
    }
}

// Broadcast chat message to all users
void broadcast_chat_message(const ChatMessage* msg) {
    char chat_data[1500];
    snprintf(chat_data, sizeof(chat_data), "CHAT_MSG:%d:%s:%ld:%d:%s",
             msg->user_id, msg->username, msg->timestamp, msg->is_ai, msg->message);
    
    EnterCriticalSection(&users_mutex);
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].active) {
            send(users[i].socket, chat_data, strlen(chat_data), 0);
        }
    }
    LeaveCriticalSection(&users_mutex);
}

// Send chat history to a client
void send_chat_history(SOCKET client_socket) {
    EnterCriticalSection(&document.lock);
    for (int i = 0; i < document.chat_count; i++) {
        char chat_data[1500];
        snprintf(chat_data, sizeof(chat_data), "CHAT_MSG:%d:%s:%ld:%d:%s",
                 document.chat_messages[i].user_id, 
                 document.chat_messages[i].username,
                 document.chat_messages[i].timestamp, 
                 document.chat_messages[i].is_ai,
                 document.chat_messages[i].message);
        send(client_socket, chat_data, strlen(chat_data), 0);
    }
    LeaveCriticalSection(&document.lock);
}

// 1. authenticate_user function
int authenticate_user(SOCKET client_socket) {
    char buffer[256];
    char username[MAX_USERNAME];
    char password[50];
    char password_hash[65];
    int bytes_read;
    int is_new_user = 0;
    
    printf("Starting authentication process...\n");
    
    // Step 1: Request username
    if (send(client_socket, "AUTH:Please enter username:", 28, 0) == SOCKET_ERROR) {
        printf("Send username prompt failed: %d\n", WSAGetLastError());
        return -1;
    }
    
    bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        printf("Client disconnected during username entry\n");
        return -1;
    }
    buffer[bytes_read] = '\0';
    
    // Parse username from message format "USER:username"
    if (sscanf(buffer, "USER:%49s", username) != 1) {
        send_error(client_socket, "Invalid username format. Use: USER:yourname");
        return -1;
    }
    
    // Step 2: Request password
    if (send(client_socket, "AUTH:Please enter password:", 28, 0) == SOCKET_ERROR) {
        printf("Send password prompt failed: %d\n", WSAGetLastError());
        return -1;
    }
    
    bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        printf("Client disconnected during password entry\n");
        return -1;
    }
    buffer[bytes_read] = '\0';
    
    // Parse password from message format "PASS:password"
    if (sscanf(buffer, "PASS:%49s", password) != 1) {
        send_error(client_socket, "Invalid password format. Use: PASS:yourpassword");
        return -1;
    }
    
    printf("Received credentials - Username: %s, Password: [hidden]\n", username);
    
    // Validate input
    if (strlen(username) < 3) {
        send_error(client_socket, "Username must be at least 3 characters");
        return -1;
    }
    if (strlen(password) < 3) {
        send_error(client_socket, "Password must be at least 3 characters");
        return -1;
    }
    
    // Hash the password
    if (!hash_password(password, password_hash)) {
        send_error(client_socket, "Authentication system error");
        return -1;
    }
    
    printf("Password hashed successfully\n");
    
    EnterCriticalSection(&users_mutex);
    
    // Check if user exists in database
    int user_db_index = -1;
    for (int i = 0; i < user_db_count; i++) {
        if (strcmp(user_database[i].username, username) == 0) {
            user_db_index = i;
            break;
        }
    }
    
    if (user_db_index == -1) {
        // New user - register them
        printf("New user detected, creating account...\n");
        if (user_db_count >= 100) {
            LeaveCriticalSection(&users_mutex);
            send_error(client_socket, "User database full. Cannot create new account.");
            return -1;
        }
        
        user_db_index = user_db_count++;
        strcpy(user_database[user_db_index].username, username);
        strcpy(user_database[user_db_index].password_hash, password_hash);
        user_database[user_db_index].user_id = user_db_index;
        is_new_user = 1;
        
        printf("New user registered: %s (DB ID: %d)\n", username, user_db_index);
    } else {
        // Existing user - verify password
        printf("Existing user found, verifying password...\n");
        if (strcmp(user_database[user_db_index].password_hash, password_hash) != 0) {
            LeaveCriticalSection(&users_mutex);
            send_error(client_socket, "Invalid password");
            return -1;
        }
        printf("Password verified successfully\n");
    }
    
    // Check if user already has an active session
    int user_id = -1;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].active && users[i].id == user_database[user_db_index].user_id) {
            // Close existing session if same user reconnects
            printf("Closing existing session for user %s\n", username);
            if (users[i].socket != INVALID_SOCKET) {
                closesocket(users[i].socket);
            }
            user_id = i;
            break;
        }
    }
    
    if (user_id == -1) {
        // Find free slot for new session
        for (int i = 0; i < MAX_USERS; i++) {
            if (!users[i].active) {
                user_id = i;
                break;
            }
        }
        
        if (user_id == -1) {
            LeaveCriticalSection(&users_mutex);
            send_error(client_socket, "Server full - too many active users");
            return -1;
        }
        
        // Initialize new user session
        users[user_id].id = user_database[user_db_index].user_id;
        strcpy(users[user_id].username, username);
        users[user_id].cursor_position = 0;
        users[user_id].last_activity = time(NULL);
        strcpy(users[user_id].color, user_colors[user_id % 8]);
        users[user_id].is_ai = 0;
        
        user_count++;
        printf("New session created for user %s (Session ID: %d)\n", username, user_id);
    }
    
    // Update user session
    users[user_id].active = 1;
    users[user_id].socket = client_socket;
    users[user_id].last_activity = time(NULL);
    
    LeaveCriticalSection(&users_mutex);
    
    // Send appropriate welcome message
    char welcome_msg[256];
    if (is_new_user) {
        snprintf(welcome_msg, sizeof(welcome_msg), 
                 "AUTH_SUCCESS:Account created! Welcome %s! Online users: %d", 
                 username, user_count);
    } else {
        snprintf(welcome_msg, sizeof(welcome_msg), 
                 "AUTH_SUCCESS:Welcome back %s! Online users: %d", 
                 username, user_count);
    }
    
    send_success(client_socket, welcome_msg);
    printf("User %s fully authenticated (Session ID: %d, Total online: %d)\n", 
           username, user_id, user_count);
    
    return user_id;
}

// 2. send_document_state function
void send_document_state(SOCKET client_socket) {
    EnterCriticalSection(&document.lock);
    
    char doc_message[MAX_DOCUMENT_SIZE + 50];
    int message_len = snprintf(doc_message, sizeof(doc_message), "DOCUMENT:%s", document.content);
    
    if (message_len > 0) {
        if (send(client_socket, doc_message, message_len, 0) == SOCKET_ERROR) {
            printf("Error sending document state: %d\n", WSAGetLastError());
        } else {
            printf("Document state sent successfully (%d bytes)\n", message_len);
        }
    }
    
    LeaveCriticalSection(&document.lock);
}

// 3. send_user_list function
void send_user_list(SOCKET client_socket) {
    EnterCriticalSection(&users_mutex);
    
    char user_list[1024] = "USERLIST:";
    int list_length = strlen(user_list);
    
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].active) {
            // Format: username,color,cursor_position;
            char user_info[100];
            int info_len = snprintf(user_info, sizeof(user_info), "%s,%s,%d;", 
                                   users[i].username, users[i].color, users[i].cursor_position);
            
            if (list_length + info_len < sizeof(user_list) - 1) {
                strcat(user_list, user_info);
                list_length += info_len;
            } else {
                break; // Buffer full
            }
        }
    }
    
    if (send(client_socket, user_list, strlen(user_list), 0) == SOCKET_ERROR) {
        printf("Error sending user list: %d\n", WSAGetLastError());
    } else {
        printf("User list sent successfully\n");
    }
    
    LeaveCriticalSection(&users_mutex);
}

// 4. process_client_message function (Enhanced with GUI support)
void process_client_message(SOCKET client_socket, char* message) {
    // Find user
    int user_id = -1;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].active && users[i].socket == client_socket) {
            user_id = i;
            break;
        }
    }
    
    if (user_id == -1) {
        send_error(client_socket, "User session not found. Please reauthenticate.");
        return;
    }
    
    // Update last activity
    users[user_id].last_activity = time(NULL);
    printf("Processing message from %s: %.50s...\n", users[user_id].username, message);
    
    // Parse different message types
    if (strncmp(message, "INSERT:", 7) == 0) {
        int position;
        char content[1000];
        if (sscanf(message, "INSERT:%d:%[^\n]", &position, content) == 2) {
            EnterCriticalSection(&document.lock);
            
            // Check if document is locked by another user
            if (document.locked_by != NULL && document.locked_by != &users[user_id]) {
                send_error(client_socket, "Document is locked by another user");
            } else if (position >= 0 && position <= document.length) {
                int content_len = strlen(content);
                if (document.length + content_len < MAX_DOCUMENT_SIZE) {
                    // Make space and insert
                    memmove(document.content + position + content_len,
                           document.content + position,
                           document.length - position);
                    memcpy(document.content + position, content, content_len);
                    document.length += content_len;
                    document.content[document.length] = '\0';
                    
                    send_success(client_socket, "INSERT_SUCCESS");
                    printf("User %s inserted %d chars at position %d\n", 
                           users[user_id].username, content_len, position);
                } else {
                    send_error(client_socket, "Document too large");
                }
            } else {
                send_error(client_socket, "Invalid insert position");
            }
            
            LeaveCriticalSection(&document.lock);
        } else {
            send_error(client_socket, "Invalid INSERT format. Use: INSERT:position:text");
        }
        
    } else if (strncmp(message, "DELETE:", 7) == 0) {
        int position, length;
        if (sscanf(message, "DELETE:%d:%d", &position, &length) == 2) {
            EnterCriticalSection(&document.lock);
            
            // Check if document is locked by another user
            if (document.locked_by != NULL && document.locked_by != &users[user_id]) {
                send_error(client_socket, "Document is locked by another user");
            } else if (position >= 0 && position + length <= document.length) {
                // Remove content
                memmove(document.content + position,
                       document.content + position + length,
                       document.length - position - length);
                document.length -= length;
                document.content[document.length] = '\0';
                
                send_success(client_socket, "DELETE_SUCCESS");
                printf("User %s deleted %d chars from position %d\n", 
                       users[user_id].username, length, position);
            } else {
                send_error(client_socket, "Invalid delete range");
            }
            
            LeaveCriticalSection(&document.lock);
        } else {
            send_error(client_socket, "Invalid DELETE format. Use: DELETE:position:length");
        }
        
    } else if (strncmp(message, "CURSOR:", 7) == 0) {
        int position;
        if (sscanf(message, "CURSOR:%d", &position) == 1) {
            users[user_id].cursor_position = position;
            printf("User %s cursor moved to position %d\n", users[user_id].username, position);
        }
        
    } else if (strncmp(message, "LOCK:", 5) == 0) {
        EnterCriticalSection(&document.lock);
        if (document.locked_by == NULL) {
            document.locked_by = &users[user_id];
            document.lock_time = time(NULL);
            send_success(client_socket, "LOCK_ACQUIRED");
            printf("User %s acquired document lock\n", users[user_id].username);
        } else if (document.locked_by == &users[user_id]) {
            send_success(client_socket, "LOCK_ALREADY_HELD");
        } else {
            send_error(client_socket, "Document locked by another user");
        }
        LeaveCriticalSection(&document.lock);
        
    } else if (strncmp(message, "UNLOCK:", 7) == 0) {
        EnterCriticalSection(&document.lock);
        if (document.locked_by == &users[user_id]) {
            document.locked_by = NULL;
            send_success(client_socket, "LOCK_RELEASED");
            printf("User %s released document lock\n", users[user_id].username);
        } else {
            send_error(client_socket, "You don't hold the lock");
        }
        LeaveCriticalSection(&document.lock);
        
    } else if (strncmp(message, "SYNC:", 5) == 0) {
        send_document_state(client_socket);
        send_user_list(client_socket);
        send_chat_history(client_socket);
        printf("Sent sync data to user %s\n", users[user_id].username);
        
    } else if (strncmp(message, "GET_STATS:", 10) == 0) {
        char stats[100];
        EnterCriticalSection(&document.lock);
        snprintf(stats, sizeof(stats), "STATS:Chars:%d Users:%d Locked:%s", 
                 document.length, user_count, 
                 document.locked_by ? document.locked_by->username : "No");
        LeaveCriticalSection(&document.lock);
        send(client_socket, stats, strlen(stats), 0);
        
    } else if (strncmp(message, "CHAT:", 5) == 0) {
        char chat_msg[1000];
        sscanf(message, "CHAT:%[^\n]", chat_msg);
        
        // Create chat message
        ChatMessage msg;
        msg.user_id = user_id;
        strcpy(msg.username, users[user_id].username);
        strcpy(msg.message, chat_msg);
        msg.timestamp = time(NULL);
        msg.is_ai = 0;
        
        // Store in document history
        EnterCriticalSection(&document.lock);
        if (document.chat_count < MAX_CHAT_MESSAGES) {
            document.chat_messages[document.chat_count++] = msg;
        } else {
            // Remove oldest message
            memmove(document.chat_messages, document.chat_messages + 1, 
                   sizeof(ChatMessage) * (MAX_CHAT_MESSAGES - 1));
            document.chat_messages[MAX_CHAT_MESSAGES - 1] = msg;
        }
        LeaveCriticalSection(&document.lock);
        
        // Broadcast to all users
        broadcast_chat_message(&msg);
        
        printf("User %s sent chat: %s\n", users[user_id].username, chat_msg);
        
    } else {
        send_error(client_socket, "Unknown command");
    }
}

// Client handling thread
unsigned __stdcall handle_client(void* arg) {
    SOCKET client_socket = *(SOCKET*)arg;
    free(arg);
    
    char buffer[8192];
    int bytes_read;
    
    printf("New client connection, starting authentication...\n");
    
    // Authenticate user
    int user_id = authenticate_user(client_socket);
    if (user_id == -1) {
        printf("Authentication failed, closing connection\n");
        closesocket(client_socket);
        return 0;
    }
    
    printf("Authentication successful, sending initial state...\n");
    
    // Send current state
    send_document_state(client_socket);
    send_user_list(client_socket);
    send_chat_history(client_socket);
    
    // Main client message loop
    while ((bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        process_client_message(client_socket, buffer);
    }
    
    // Client disconnected
    printf("User %s disconnected\n", users[user_id].username);
    
    EnterCriticalSection(&users_mutex);
    users[user_id].active = 0;
    users[user_id].socket = INVALID_SOCKET;
    user_count--;
    LeaveCriticalSection(&users_mutex);
    
    // Release lock if held by this user
    EnterCriticalSection(&document.lock);
    if (document.locked_by == &users[user_id]) {
        document.locked_by = NULL;
        printf("Lock released by disconnected user %s\n", users[user_id].username);
    }
    LeaveCriticalSection(&document.lock);
    
    closesocket(client_socket);
    return 0;
}

// Background thread for broadcasting updates (Enhanced for GUI)
unsigned __stdcall broadcast_updates(void* arg) {
    while (1) {
        Sleep(2000); // Broadcast every 2 seconds
        
        EnterCriticalSection(&users_mutex);
        
        // Only broadcast if there are active users
        if (user_count > 0) {
            // Prepare user positions message
            char user_positions[1024] = "USERS:";
            for (int i = 0; i < MAX_USERS; i++) {
                if (users[i].active) {
                    char user_info[100];
                    snprintf(user_info, sizeof(user_info), "%s,%d,%s;", 
                             users[i].username, users[i].cursor_position, users[i].color);
                    strcat(user_positions, user_info);
                }
            }
            
            // Document stats
            char stats[100];
            EnterCriticalSection(&document.lock);
            snprintf(stats, sizeof(stats), "STATS:Chars:%d Users:%d Locked:%s", 
                     document.length, user_count, 
                     document.locked_by ? document.locked_by->username : "No");
            LeaveCriticalSection(&document.lock);
            
            // Broadcast to all users
            for (int i = 0; i < MAX_USERS; i++) {
                if (users[i].active) {
                    send(users[i].socket, user_positions, strlen(user_positions), 0);
                    send(users[i].socket, stats, strlen(stats), 0);
                }
            }
        }
        
        LeaveCriticalSection(&users_mutex);
    }
    return 0;
}

// Background thread for checking lock timeouts
unsigned __stdcall check_locks(void* arg) {
    while (1) {
        Sleep(5000); // Check every 5 seconds
        
        EnterCriticalSection(&document.lock);
        if (document.locked_by != NULL && 
            time(NULL) - document.lock_time > LOCK_TIMEOUT) {
            printf("Lock timeout for user %s\n", document.locked_by->username);
            document.locked_by = NULL;
        }
        LeaveCriticalSection(&document.lock);
    }
    return 0;
}

void initialize_document() {
    strcpy(document.content, "Welcome to Secure Collaborative Editor!\n\n"
                           "This is a secure multi-user editor with password hashing.\n"
                           "You can:\n"
                           "- Edit text collaboratively\n" 
                           "- Lock the document for exclusive editing\n"
                           "- See other users' cursors in real-time\n"
                           "- Chat with other users\n\n"
                           "Start editing...\n");
    document.length = strlen(document.content);
    document.locked_by = NULL;
    document.chat_count = 0;
    InitializeCriticalSection(&document.lock);
    
    printf("Document initialized with %d characters\n", document.length);
}

int main() {
    WSADATA wsaData;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    
    printf("=== Secure Collaborative Editor Server ===\n");
    printf("Initializing...\n");
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Initialize mutexes
    InitializeCriticalSection(&users_mutex);
    
    // Initialize document and user database
    initialize_document();
    user_db_count = 0; // Start with empty user database
    
    // Initialize users array
    for (int i = 0; i < MAX_USERS; i++) {
        users[i].active = 0;
        users[i].socket = INVALID_SOCKET;
        users[i].is_ai = 0;
    }
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("Setsockopt failed: %d\n", WSAGetLastError());
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);
    printf("Waiting for connections...\n");
    
    // Start background threads
    _beginthreadex(NULL, 0, broadcast_updates, NULL, 0, NULL);
    _beginthreadex(NULL, 0, check_locks, NULL, 0, NULL);
    
    // Main accept loop
    while (1) {
        SOCKET client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        printf("\n=== New connection from %s:%d ===\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Create thread for new client
        SOCKET* client_sock_ptr = (SOCKET*)malloc(sizeof(SOCKET));
        if (client_sock_ptr == NULL) {
            printf("Memory allocation failed for client socket\n");
            closesocket(client_socket);
            continue;
        }
        *client_sock_ptr = client_socket;
        
        HANDLE thread_handle = (HANDLE)_beginthreadex(NULL, 0, handle_client, (void*)client_sock_ptr, 0, NULL);
        if (thread_handle == 0) {
            printf("Thread creation failed\n");
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            CloseHandle(thread_handle); // We don't need to keep the handle
        }
    }
    
    // Cleanup (theoretically unreachable in this simple server)
    closesocket(server_socket);
    WSACleanup();
    DeleteCriticalSection(&document.lock);
    DeleteCriticalSection(&users_mutex);
    
    return 0;
}