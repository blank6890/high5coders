#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_BUFFER_SIZE 4096
#define MAX_USERS 100
#define MAX_ORGS 50
#define MAX_FILES 1000
#define USER_FILE "users.txt"
#define ORG_FILE "organizations.txt"
#define FILES_FILE "files.txt"

typedef struct {
    char username[50];
    char password[50];
} User;

typedef struct {
    char code[7]; // 6-character code + null terminator
    char name[100];
    char password[50];
    char creator[50];
    int member_count;
    char members[50][50]; // Array of usernames
} Organization;

typedef struct {
    char id[50];
    char filename[100];
    char content[4096];
    char owner[50];
    char org_code[7]; // Empty if personal file
    time_t created_at;
    time_t modified_at;
} File;

User users[MAX_USERS];
Organization organizations[MAX_ORGS];
File files[MAX_FILES];
int user_count = 0;
int org_count = 0;
int file_count = 0;

// Function to generate random organization code
void generate_org_code(char *code) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 6; i++) {
        code[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    code[6] = '\0';
}

// Function to generate unique file ID
void generate_file_id(char *id, const char *prefix) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    snprintf(id, 50, "%s_", prefix);
    int len = strlen(id);
    for (int i = 0; i < 10; i++) {
        id[len + i] = charset[rand() % (sizeof(charset) - 1)];
    }
    id[len + 10] = '\0';
}

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
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
                continue;
            }
            
            line[strcspn(line, "\r\n")] = 0;
            
            char username[50] = {0};
            char password[50] = {0};
            
            if (sscanf(line, "%49s %49s", username, password) == 2) {
                strcpy(users[user_count].username, username);
                strcpy(users[user_count].password, password);
                printf("  Loaded user %d: %s / %s\n", user_count + 1, username, password);
                user_count++;
            }
        }
        fclose(file);
        printf("Total users loaded: %d\n\n", user_count);
        
        if (user_count == 0) {
            create_users_file();
            load_users();
        }
    } else {
        printf("Users file not found. Creating new one...\n");
        create_users_file();
        load_users();
    }
}

// Function to load organizations from file
void load_organizations() {
    FILE *file = fopen(ORG_FILE, "r");
    if (file) {
        org_count = 0;
        char line[1024];
        
        printf("Loading organizations from %s:\n", ORG_FILE);
        
        while (fgets(line, sizeof(line), file) && org_count < MAX_ORGS) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
                continue;
            }
            
            line[strcspn(line, "\r\n")] = 0;
            
            Organization org;
            char *token = strtok(line, "|");
            int field = 0;
            
            while (token != NULL) {
                switch (field) {
                    case 0: strcpy(org.code, token); break;
                    case 1: strcpy(org.name, token); break;
                    case 2: strcpy(org.password, token); break;
                    case 3: strcpy(org.creator, token); break;
                    case 4: org.member_count = atoi(token); break;
                    default: 
                        if (field - 5 < org.member_count && field - 5 < 50) {
                            strcpy(org.members[field - 5], token);
                        }
                        break;
                }
                token = strtok(NULL, "|");
                field++;
            }
            
            organizations[org_count] = org;
            printf("  Loaded org: %s (%s) - %d members\n", org.code, org.name, org.member_count);
            org_count++;
        }
        fclose(file);
        printf("Total organizations loaded: %d\n\n", org_count);
    } else {
        printf("Organizations file not found. Creating empty database.\n");
        // Create empty file
        file = fopen(ORG_FILE, "w");
        if (file) {
            fprintf(file, "# Organization Database\n");
            fprintf(file, "# Format: code|name|password|creator|member_count|member1|member2|...\n\n");
            fclose(file);
        }
    }
}

// Function to load files from file
void load_files() {
    FILE *file = fopen(FILES_FILE, "r");
    if (file) {
        file_count = 0;
        char line[8192]; // Larger buffer for file content
        
        printf("Loading files from %s:\n", FILES_FILE);
        
        while (fgets(line, sizeof(line), file) && file_count < MAX_FILES) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
                continue;
            }
            
            line[strcspn(line, "\r\n")] = 0;
            
            File f;
            char *token = strtok(line, "|");
            int field = 0;
            
            while (token != NULL) {
                switch (field) {
                    case 0: strcpy(f.id, token); break;
                    case 1: strcpy(f.filename, token); break;
                    case 2: strcpy(f.content, token); break;
                    case 3: strcpy(f.owner, token); break;
                    case 4: strcpy(f.org_code, token); break;
                    case 5: f.created_at = atol(token); break;
                    case 6: f.modified_at = atol(token); break;
                }
                token = strtok(NULL, "|");
                field++;
            }
            
            files[file_count] = f;
            printf("  Loaded file: %s (%s)\n", f.filename, f.owner);
            file_count++;
        }
        fclose(file);
        printf("Total files loaded: %d\n\n", file_count);
    } else {
        printf("Files database not found. Creating empty database.\n");
        file = fopen(FILES_FILE, "w");
        if (file) {
            fprintf(file, "# Files Database\n");
            fprintf(file, "# Format: id|filename|content|owner|org_code|created_at|modified_at\n\n");
            fclose(file);
        }
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

// Function to save ALL organizations to file
void save_all_organizations() {
    FILE *file = fopen(ORG_FILE, "w");
    if (file) {
        fprintf(file, "# Organization Database\n");
        fprintf(file, "# Format: code|name|password|creator|member_count|member1|member2|...\n\n");
        
        for (int i = 0; i < org_count; i++) {
            fprintf(file, "%s|%s|%s|%s|%d", 
                   organizations[i].code,
                   organizations[i].name,
                   organizations[i].password,
                   organizations[i].creator,
                   organizations[i].member_count);
            
            for (int j = 0; j < organizations[i].member_count; j++) {
                fprintf(file, "|%s", organizations[i].members[j]);
            }
            fprintf(file, "\n");
        }
        fclose(file);
        printf("Saved ALL %d organizations to %s\n", org_count, ORG_FILE);
    } else {
        printf("ERROR: Could not save organizations to file!\n");
    }
}

// Function to save ALL files to file
void save_all_files() {
    FILE *file = fopen(FILES_FILE, "w");
    if (file) {
        fprintf(file, "# Files Database\n");
        fprintf(file, "# Format: id|filename|content|owner|org_code|created_at|modified_at\n\n");
        
        for (int i = 0; i < file_count; i++) {
            fprintf(file, "%s|%s|%s|%s|%s|%ld|%ld\n",
                   files[i].id,
                   files[i].filename,
                   files[i].content,
                   files[i].owner,
                   files[i].org_code,
                   files[i].created_at,
                   files[i].modified_at);
        }
        fclose(file);
        printf("Saved ALL %d files to %s\n", file_count, FILES_FILE);
    } else {
        printf("ERROR: Could not save files to file!\n");
    }
}

// Function to verify user credentials
int verify_user(const char *username, const char *password) {
    printf("Verifying user: '%s' with password: '%s'\n", username, password);
    
    for (int i = 0; i < user_count; i++) {
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

// Function to create new organization
int create_organization(const char *org_name, const char *org_password, const char *creator) {
    printf("Creating organization: %s by %s\n", org_name, creator);
    
    if (org_count >= MAX_ORGS) {
        printf("Error: Maximum organization limit reached\n");
        return 0;
    }
    
    // Generate unique organization code
    char org_code[7];
    int unique = 0;
    while (!unique) {
        generate_org_code(org_code);
        unique = 1;
        for (int i = 0; i < org_count; i++) {
            if (strcmp(organizations[i].code, org_code) == 0) {
                unique = 0;
                break;
            }
        }
    }
    
    // Create organization
    Organization org;
    strcpy(org.code, org_code);
    strcpy(org.name, org_name);
    strcpy(org.password, org_password);
    strcpy(org.creator, creator);
    org.member_count = 1;
    strcpy(org.members[0], creator); // Creator is first member
    
    organizations[org_count] = org;
    org_count++;
    
    // Save organizations
    save_all_organizations();
    
    printf("Organization '%s' created with code: %s\n", org_name, org_code);
    return 1;
}

// Function to join organization
int join_organization(const char *org_code, const char *org_password, const char *username) {
    printf("User '%s' attempting to join organization: %s\n", username, org_code);
    
    for (int i = 0; i < org_count; i++) {
        if (strcmp(organizations[i].code, org_code) == 0) {
            // Check password
            if (strcmp(organizations[i].password, org_password) != 0) {
                printf("  ❌ Invalid organization password\n");
                return 0;
            }
            
            // Check if user is already a member
            for (int j = 0; j < organizations[i].member_count; j++) {
                if (strcmp(organizations[i].members[j], username) == 0) {
                    printf("  ⚠️ User already a member of this organization\n");
                    return 1; // Already a member, but still success
                }
            }
            
            // Add user to organization
            if (organizations[i].member_count < 50) {
                strcpy(organizations[i].members[organizations[i].member_count], username);
                organizations[i].member_count++;
                
                // Save organizations
                save_all_organizations();
                
                printf("  ✅ User '%s' added to organization '%s'\n", username, organizations[i].name);
                return 1;
            } else {
                printf("  ❌ Organization member limit reached\n");
                return 0;
            }
        }
    }
    
    printf("  ❌ Organization not found: %s\n", org_code);
    return 0;
}

// Function to create new file
int create_file(const char *filename, const char *content, const char *owner, const char *org_code) {
    printf("Creating file: %s for user %s in org %s\n", filename, owner, org_code);
    
    if (file_count >= MAX_FILES) {
        printf("Error: Maximum file limit reached\n");
        return 0;
    }
    
    // Generate file ID
    File new_file;
    generate_file_id(new_file.id, "file");
    strcpy(new_file.filename, filename);
    strcpy(new_file.content, content);
    strcpy(new_file.owner, owner);
    strcpy(new_file.org_code, org_code);
    new_file.created_at = time(NULL);
    new_file.modified_at = time(NULL);
    
    files[file_count] = new_file;
    file_count++;
    
    // Save files
    save_all_files();
    
    printf("File '%s' created with ID: %s\n", filename, new_file.id);
    return 1;
}

// Function to get organization by code
Organization* get_organization(const char *org_code) {
    for (int i = 0; i < org_count; i++) {
        if (strcmp(organizations[i].code, org_code) == 0) {
            return &organizations[i];
        }
    }
    return NULL;
}

// Function to get files for user/organization
int get_user_files(const char *username, const char *org_code, File *result_files, int max_results) {
    int count = 0;
    
    for (int i = 0; i < file_count && count < max_results; i++) {
        // Personal files (no org) or files in specified organization
        if ((strlen(org_code) == 0 && strlen(files[i].org_code) == 0 && strcmp(files[i].owner, username) == 0) ||
            (strlen(org_code) > 0 && strcmp(files[i].org_code, org_code) == 0)) {
            result_files[count] = files[i];
            count++;
        }
    }
    
    return count;
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

// Parse organization creation data
void parse_org_data(const char *data, char *org_name, char *org_password, char *username) {
    printf("Raw org data: %s\n", data);
    
    char buffer[MAX_BUFFER_SIZE];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, "&");
    while (token != NULL) {
        if (strncmp(token, "orgName=", 8) == 0) {
            strncpy(org_name, token + 8, 99);
            url_decode(org_name);
        } else if (strncmp(token, "orgPassword=", 12) == 0) {
            strncpy(org_password, token + 12, 49);
            url_decode(org_password);
        } else if (strncmp(token, "username=", 9) == 0) {
            strncpy(username, token + 9, 49);
            url_decode(username);
        }
        token = strtok(NULL, "&");
    }
    
    printf("Parsed org - Name: '%s', Password: '%s', Creator: '%s'\n", org_name, org_password, username);
}

// Parse organization join data
void parse_join_org_data(const char *data, char *org_code, char *org_password, char *username) {
    printf("Raw join org data: %s\n", data);
    
    char buffer[MAX_BUFFER_SIZE];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, "&");
    while (token != NULL) {
        if (strncmp(token, "orgCode=", 8) == 0) {
            strncpy(org_code, token + 8, 6);
            url_decode(org_code);
        } else if (strncmp(token, "orgPassword=", 12) == 0) {
            strncpy(org_password, token + 12, 49);
            url_decode(org_password);
        } else if (strncmp(token, "username=", 9) == 0) {
            strncpy(username, token + 9, 49);
            url_decode(username);
        }
        token = strtok(NULL, "&");
    }
    
    printf("Parsed join org - Code: '%s', Password: '%s', User: '%s'\n", org_code, org_password, username);
}

// Parse file data
void parse_file_data(const char *data, char *filename, char *content, char *owner, char *org_code) {
    printf("Raw file data: %s\n", data);
    
    char buffer[MAX_BUFFER_SIZE];
    strncpy(buffer, data, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, "&");
    while (token != NULL) {
        if (strncmp(token, "filename=", 9) == 0) {
            strncpy(filename, token + 9, 99);
            url_decode(filename);
        } else if (strncmp(token, "content=", 8) == 0) {
            strncpy(content, token + 8, 4095);
            url_decode(content);
        } else if (strncmp(token, "owner=", 6) == 0) {
            strncpy(owner, token + 6, 49);
            url_decode(owner);
        } else if (strncmp(token, "orgCode=", 8) == 0) {
            strncpy(org_code, token + 8, 6);
            url_decode(org_code);
        }
        token = strtok(NULL, "&");
    }
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

// Create HTTP response with organization code
char* create_org_response(int status, const char *message, const char *org_code) {
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
        "{\"status\":\"%s\",\"message\":\"%s\",\"orgCode\":\"%s\"}",
        status, status_text, status == 200 ? "success" : "error", message, org_code);
    
    return response;
}

// Create HTTP response with organization info
char* create_join_org_response(int status, const char *message, const char *org_name) {
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
        "{\"status\":\"%s\",\"message\":\"%s\",\"orgName\":\"%s\"}",
        status, status_text, status == 200 ? "success" : "error", message, org_name);
    
    return response;
}

// Create HTTP response with files data
char* create_files_response(int status, File *files, int count) {
    static char response[MAX_BUFFER_SIZE];
    const char *status_text = status == 200 ? "OK" : "Bad Request";
    
    char files_json[2048] = "";
    for (int i = 0; i < count; i++) {
        char file_json[512];
        snprintf(file_json, sizeof(file_json),
            "%s{\"id\":\"%s\",\"filename\":\"%s\",\"content\":\"%s\",\"owner\":\"%s\",\"org_code\":\"%s\",\"created_at\":%ld,\"modified_at\":%ld}",
            i > 0 ? "," : "", files[i].id, files[i].filename, files[i].content, files[i].owner, files[i].org_code, files[i].created_at, files[i].modified_at);
        strncat(files_json, file_json, sizeof(files_json) - strlen(files_json) - 1);
    }
    
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"%s\",\"files\":[%s]}",
        status, status_text, status == 200 ? "success" : "error", files_json);
    
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
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    printf("=== Text Editor with Organizations Server ===\n");
    printf("Initializing databases...\n");
    load_users();
    load_organizations();
    load_files();
    
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
    printf("  http://localhost:%d/              - Dashboard\n", PORT);
    printf("  http://localhost:%d/login         - Login page\n", PORT);
    printf("  http://localhost:%d/create_org    - Create organization\n", PORT);
    printf("  http://localhost:%d/org_login     - Join organization\n", PORT);
    printf("  http://localhost:%d/dashboard     - Dashboard\n", PORT);
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
            if (strstr(buffer, "GET / ") || strstr(buffer, "GET /dashboard") || 
                (strstr(buffer, "GET /") && !strstr(buffer, "GET /login") && 
                 !strstr(buffer, "GET /create_org") && !strstr(buffer, "GET /org_login"))) {
                printf("📄 Serving dashboard\n");
                serve_html_file(client_socket, "dashboard.html");
            }
            else if (strstr(buffer, "GET /login")) {
                printf("📄 Serving login page\n");
                serve_html_file(client_socket, "login.html");
            }
            else if (strstr(buffer, "GET /create_org")) {
                printf("📄 Serving create organization page\n");
                serve_html_file(client_socket, "create_org.html");
            }
            else if (strstr(buffer, "GET /org_login")) {
                printf("📄 Serving organization login page\n");
                serve_html_file(client_socket, "org_login.html");
            }
            // Handle organization creation
            else if (strstr(buffer, "POST /create_org")) {
                printf("🏢 Processing ORGANIZATION CREATION request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char org_name[100] = {0};
                    char org_password[50] = {0};
                    char username[50] = {0};
                    
                    parse_org_data(body, org_name, org_password, username);
                    
                    printf("Organization creation: name='%s', creator='%s'\n", org_name, username);
                    
                    // Validate input
                    if (strlen(org_name) < 2) {
                        printf("Validation failed: Organization name too short\n");
                        char *response = create_response(400, "Organization name must be at least 2 characters");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(org_password) < 4) {
                        printf("Validation failed: Organization password too short\n");
                        char *response = create_response(400, "Organization password must be at least 4 characters");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        // Create organization
                        if (create_organization(org_name, org_password, username)) {
                            // Find the created organization to get its code
                            for (int i = 0; i < org_count; i++) {
                                if (strcmp(organizations[i].creator, username) == 0 && 
                                    strcmp(organizations[i].name, org_name) == 0) {
                                    char *response = create_org_response(200, "Organization created successfully", organizations[i].code);
                                    send(client_socket, response, strlen(response), 0);
                                    break;
                                }
                            }
                        } else {
                            char *response = create_response(400, "Failed to create organization");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            // Handle organization join
            else if (strstr(buffer, "POST /join_org")) {
                printf("🔐 Processing ORGANIZATION JOIN request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char org_code[7] = {0};
                    char org_password[50] = {0};
                    char username[50] = {0};
                    
                    parse_join_org_data(body, org_code, org_password, username);
                    
                    printf("Organization join: code='%s', user='%s'\n", org_code, username);
                    
                    // Validate input
                    if (strlen(org_code) != 6) {
                        printf("Validation failed: Invalid organization code\n");
                        char *response = create_response(400, "Invalid organization code");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(org_password) == 0) {
                        printf("Validation failed: Empty organization password\n");
                        char *response = create_response(400, "Please enter organization password");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        // Join organization
                        if (join_organization(org_code, org_password, username)) {
                            // Get organization name for response
                            Organization *org = get_organization(org_code);
                            if (org) {
                                char *response = create_join_org_response(200, "Successfully joined organization", org->name);
                                send(client_socket, response, strlen(response), 0);
                            } else {
                                char *response = create_response(400, "Organization not found");
                                send(client_socket, response, strlen(response), 0);
                            }
                        } else {
                            char *response = create_response(400, "Invalid organization code or password");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            // Handle file creation
            else if (strstr(buffer, "POST /create_file")) {
                printf("📝 Processing FILE CREATION request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char filename[100] = {0};
                    char content[4096] = {0};
                    char owner[50] = {0};
                    char org_code[7] = {0};
                    
                    parse_file_data(body, filename, content, owner, org_code);
                    
                    printf("File creation: filename='%s', owner='%s', org='%s'\n", filename, owner, org_code);
                    
                    // Validate input
                    if (strlen(filename) == 0) {
                        printf("Validation failed: Empty filename\n");
                        char *response = create_response(400, "Please enter filename");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        // Create file
                        if (create_file(filename, content, owner, org_code)) {
                            char *response = create_response(200, "File created successfully");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_response(400, "Failed to create file");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            // Handle get files
            else if (strstr(buffer, "GET /get_files")) {
                printf("📂 Processing GET FILES request\n");
                
                // Parse query parameters
                char *query_start = strstr(buffer, "?");
                if (query_start) {
                    char username[50] = {0};
                    char org_code[7] = {0};
                    
                    char *token = strtok(query_start + 1, "&");
                    while (token != NULL) {
                        if (strncmp(token, "user=", 5) == 0) {
                            strncpy(username, token + 5, 49);
                            url_decode(username);
                        } else if (strncmp(token, "org=", 4) == 0) {
                            strncpy(org_code, token + 4, 6);
                            url_decode(org_code);
                        }
                        token = strtok(NULL, "&");
                    }
                    
                    printf("Get files: user='%s', org='%s'\n", username, org_code);
                    
                    File result_files[100];
                    int count = get_user_files(username, org_code, result_files, 100);
                    
                    char *response = create_files_response(200, result_files, count);
                    send(client_socket, response, strlen(response), 0);
                } else {
                    char *response = create_response(400, "Missing parameters");
                    send(client_socket, response, strlen(response), 0);
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
            // Handle signup
            else if (strstr(buffer, "POST /signup")) {
                printf("📝 Processing SIGNUP request\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char password[50] = {0};
                    char confirm_password[50] = {0};
                    
                    // Parse signup data (simplified)
                    char *token = strtok(body, "&");
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
                printf("❓ Unknown request, serving dashboard\n");
                serve_html_file(client_socket, "dashboard.html");
            }
        }
        
        closesocket(client_socket);
        printf("--- Request processed ---\n\n");
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
}