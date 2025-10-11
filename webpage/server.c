#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_BUFFER_SIZE 4096
#define MAX_USERS 100
#define USER_FILE "users.txt"

typedef struct {
    char username[50];
    char password[50];
} User;

User users[MAX_USERS];
int user_count = 0;

// Function to create users file with demo accounts
void create_users_file() {
    FILE *file = fopen(USER_FILE, "w");
    if (file) {
        printf("Creating new users database: %s\n", USER_FILE);
        fprintf(file, "# User Database\n");
        fprintf(file, "# Format: username password\n\n");
        fprintf(file, "demo demo123\n");
        fprintf(file, "admin admin123\n");
        fclose(file);
        printf("Created default users file with demo accounts.\n");
    } else {
        printf("ERROR: Could not create users file!\n");
    }
}

// Function to load users from file
void load_users() {
    FILE *file = fopen(USER_FILE, "r");
    if (file) {
        user_count = 0;
        char line[256];
        
        printf("Loading users from %s:\n", USER_FILE);
        
        while (fgets(line, sizeof(line), file) && user_count < MAX_USERS) {
            // Skip comment lines and empty lines
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
                continue;
            }
            
            // Remove newline characters
            line[strcspn(line, "\r\n")] = 0;
            
            // Parse username and password
            char username[50] = {0};
            char password[50] = {0};
            
            if (sscanf(line, "%49s %49s", username, password) == 2) {
                strcpy(users[user_count].username, username);
                strcpy(users[user_count].password, password);
                printf("  Loaded user %d: %s / %s\n", user_count + 1, username, password);
                user_count++;
            } else {
                printf("  Warning: Could not parse line: %s\n", line);
            }
        }
        fclose(file);
        printf("Total users loaded: %d\n\n", user_count);
        
        if (user_count == 0) {
            printf("No users found in file. Creating default accounts.\n");
            create_users_file();
            load_users(); // Reload
        }
    } else {
        printf("Users file not found. Creating new one...\n");
        create_users_file();
        load_users(); // Reload after creation
    }
}

// Function to save ALL users to file
void save_all_users() {
    FILE *file = fopen(USER_FILE, "w");
    if (file) {
        fprintf(file, "# User Database\n");
        fprintf(file, "# Format: username password\n\n");
        
        for (int i = 0; i < user_count; i++) {
            fprintf(file, "%s %s\n", users[i].username, users[i].password);
        }
        fclose(file);
        printf("Saved ALL %d users to %s\n", user_count, USER_FILE);
    } else {
        printf("ERROR: Could not save users to file!\n");
    }
}

// Function to verify user credentials
int verify_user(const char *username, const char *password) {
    printf("Verifying user: '%s' with password: '%s'\n", username, password);
    
    for (int i = 0; i < user_count; i++) {
        printf("  Checking against: %s / %s\n", users[i].username, users[i].password);
        
        if (strcmp(users[i].username, username) == 0) {
            if (strcmp(users[i].password, password) == 0) {
                printf("  ✅ Login SUCCESS: User '%s' authenticated\n", username);
                return 1;
            } else {
                printf("  ❌ Login FAILED: Incorrect password for user '%s'\n", username);
                return 0;
            }
        }
    }
    printf("  ❌ Login FAILED: User '%s' not found in database\n", username);
    return 0;
}

// Function to add new user
int add_user(const char *username, const char *password) {
    printf("Adding new user: %s / %s\n", username, password);
    
    if (user_count >= MAX_USERS) {
        printf("Error: Maximum user limit reached\n");
        return 0;
    }
    
    // Check if username already exists
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            printf("Error: Username '%s' already exists\n", username);
            return 0;
        }
    }
    
    // Add user to memory
    strcpy(users[user_count].username, username);
    strcpy(users[user_count].password, password);
    user_count++;
    
    // Save ALL users to file (overwrite)
    save_all_users();
    
    printf("User '%s' successfully added to database\n", username);
    return 1;
}

// URL decode function
void url_decode(char *str) {
    if (!str) return;
    
    char *src = str;
    char *dst = str;
    char hex[3];
    
    while (*src) {
        if (*src == '%' && isxdigit(src[1]) && isxdigit(src[2])) {
            hex[0] = src[1];
            hex[1] = src[2];
            hex[2] = '\0';
            *dst = (char)strtol(hex, NULL, 16);
            src += 3;
            dst++;
        } else if (*src == '+') {
            *dst = ' ';
            src++;
            dst++;
        } else {
            *dst = *src;
            src++;
            dst++;
        }
    }
    *dst = '\0';
}

// Parse login form data
void parse_login_data(const char *data, char *username, char *password) {
    printf("Raw login data: %s\n", data);
    
    char buffer[MAX_BUFFER_SIZE];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, "&");
    while (token != NULL) {
        if (strncmp(token, "username=", 9) == 0) {
            strncpy(username, token + 9, 49);
            url_decode(username);
            printf("Parsed username: '%s'\n", username);
        } else if (strncmp(token, "password=", 9) == 0) {
            strncpy(password, token + 9, 49);
            url_decode(password);
            printf("Parsed password: '%s'\n", password);
        }
        token = strtok(NULL, "&");
    }
}

// Parse signup form data
void parse_form_data(const char *data, char *username, char *password, char *confirm_password) {
    printf("Raw signup data: %s\n", data);
    
    char buffer[MAX_BUFFER_SIZE];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, "&");
    while (token != NULL) {
        if (strncmp(token, "username=", 9) == 0) {
            strncpy(username, token + 9, 49);
            url_decode(username);
        } else if (strncmp(token, "password=", 9) == 0) {
            strncpy(password, token + 9, 49);
            url_decode(password);
        } else if (strncmp(token, "confirmPassword=", 16) == 0) {
            strncpy(confirm_password, token + 16, 49);
            url_decode(confirm_password);
        }
        token = strtok(NULL, "&");
    }
    
    printf("Parsed signup - Username: '%s', Password: '%s', Confirm: '%s'\n", 
           username, password, confirm_password);
}

// Create HTTP response
char* create_response(int status, const char *message) {
    static char response[MAX_BUFFER_SIZE];
    const char *status_text = status == 200 ? "OK" : "Bad Request";
    
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"%s\",\"message\":\"%s\"}",
        status, status_text, status == 200 ? "success" : "error", message);
    
    return response;
}

// Serve HTML file
void serve_html_file(SOCKET client_socket, const char *filename) {
    printf("Serving file: %s\n", filename);
    
    FILE *file = fopen(filename, "rb");
    if (file) {
        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        char *file_content = (char*)malloc(file_size + 1);
        if (file_content) {
            fread(file_content, 1, file_size, file);
            
            char header[512];
            snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %ld\r\n"
                "Connection: close\r\n"
                "\r\n", file_size);
            
            send(client_socket, header, strlen(header), 0);
            send(client_socket, file_content, file_size, 0);
            
            free(file_content);
        }
        fclose(file);
    } else {
        printf("ERROR: Could not open file %s\n", filename);
        const char *response = 
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<h1>404 - File Not Found</h1><p>Requested file not found</p>";
        send(client_socket, response, strlen(response), 0);
    }
}

int main() {
    WSADATA wsa;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server, client;
    int client_len = sizeof(struct sockaddr_in);
    
    printf("=== Text Editor Authentication Server ===\n");
    printf("Initializing user database...\n");
    load_users();
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Configure server
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    // Bind
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen
    if (listen(server_socket, 3) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Server running on port %d\n", PORT);
    printf("Available URLs:\n");
    printf("  http://localhost:%d/         - Signup page\n", PORT);
    printf("  http://localhost:%d/login    - Login page\n", PORT);
    printf("  http://localhost:%d/editor   - Editor page\n", PORT);
    printf("\nReady to accept connections...\n\n");
    
    // Main server loop
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        char buffer[MAX_BUFFER_SIZE] = {0};
        int bytes_received = recv(client_socket, buffer, MAX_BUFFER_SIZE - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            // Route requests
            if (strstr(buffer, "GET / ") || strstr(buffer, "GET /start.html") || 
                (strstr(buffer, "GET /") && !strstr(buffer, "GET /login") && !strstr(buffer, "GET /editor"))) {
                printf("📄 Serving signup page\n");
                serve_html_file(client_socket, "start.html");
            }
            else if (strstr(buffer, "GET /login")) {
                printf("📄 Serving login page\n");
                serve_html_file(client_socket, "login.html");
            }
            else if (strstr(buffer, "GET /editor")) {
                printf("📄 Serving editor page\n");
                serve_html_file(client_socket, "editor.html");
            }
            // Handle signup
            else if (strstr(buffer, "POST /signup")) {
                printf("📝 Processing SIGNUP request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char password[50] = {0};
                    char confirm_password[50] = {0};
                    
                    parse_form_data(body, username, password, confirm_password);
                    
                    printf("Signup attempt: username='%s'\n", username);
                    
                    // Validate input
                    if (strlen(username) < 3) {
                        printf("Validation failed: Username too short\n");
                        char *response = create_response(400, "Username must be at least 3 characters");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(password) < 8) {
                        printf("Validation failed: Password too short\n");
                        char *response = create_response(400, "Password must be at least 8 characters");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strcmp(password, confirm_password) != 0) {
                        printf("Validation failed: Passwords don't match\n");
                        char *response = create_response(400, "Passwords do not match");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        // Add user
                        if (add_user(username, password)) {
                            char *response = create_response(200, "Account created successfully");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_response(400, "Username already exists");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            // Handle login
            else if (strstr(buffer, "POST /login")) {
                printf("🔐 Processing LOGIN request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char password[50] = {0};
                    
                    parse_login_data(body, username, password);
                    
                    printf("Login attempt: username='%s', password='%s'\n", username, password);
                    
                    // Validate input
                    if (strlen(username) == 0) {
                        printf("Validation failed: Empty username\n");
                        char *response = create_response(400, "Please enter username");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(password) == 0) {
                        printf("Validation failed: Empty password\n");
                        char *response = create_response(400, "Please enter password");
                        send(client_socket, response, strlen(response), 0);
                    } else if (verify_user(username, password)) {
                        printf("✅ Login successful for user: %s\n", username);
                        char *response = create_response(200, "Login successful");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        printf("❌ Login failed for user: %s\n", username);
                        char *response = create_response(400, "Invalid username or password");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            // Handle OPTIONS (CORS)
            else if (strstr(buffer, "OPTIONS")) {
                printf("🔄 Handling OPTIONS request\n");
                const char *options_response = 
                    "HTTP/1.1 200 OK\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    "Access-Control-Allow-Headers: Content-Type\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(client_socket, options_response, strlen(options_response), 0);
            }
            else {
                printf("❓ Unknown request, serving signup page\n");
                serve_html_file(client_socket, "start.html");
            }
        }
        
        closesocket(client_socket);
        printf("--- Request processed ---\n\n");
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
}