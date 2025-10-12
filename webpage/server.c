#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <time.h>
#include <direct.h>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define MAX_BUFFER_SIZE 16384
#define MAX_USERS 100
#define MAX_ORGS 50
#define MAX_FILES 1000
#define MAX_ROLES 200
#define MAX_PRESENCE 1000
#define MAX_LOCKS 100

#define USER_FILE "users.txt"
#define ORG_FILE "organizations.txt"
#define FILES_FILE "files.txt"
#define ROLES_FILE "roles.txt"

typedef struct {
    char username[50];
    char password[100];
    char salt[50];
} User;

typedef struct {
    char code[7];
    char name[100];
    char password[100];
    char salt[50];
    char creator[50];
    int member_count;
    char members[50][50];
} Organization;

typedef struct {
    char org_code[7];
    char username[50];
    char role[20];
} UserRole;

typedef struct {
    char id[50];
    char filename[100];
    char content[8192];
    char owner[50];
    char org_code[7];
    time_t created_at;
    time_t modified_at;
    char permissions[20];
} File;

typedef struct {
    char username[50];
    char org_code[7];
    time_t last_seen;
    int is_online;
} UserPresenceRecord;

typedef struct {
    char file_id[50];
    char locked_by[50];
    time_t locked_at;
    int is_locked;
} FileLock;

User users[MAX_USERS];
Organization organizations[MAX_ORGS];
UserRole user_roles[MAX_ROLES];
File files[MAX_FILES];
UserPresenceRecord user_presence[MAX_PRESENCE];
FileLock file_locks[MAX_LOCKS];

int user_count = 0;
int org_count = 0;
int role_count = 0;
int file_count = 0;
int presence_count = 0;
int lock_count = 0;

// Generate random organization code
void generate_org_code(char *code) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 6; i++) {
        code[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    code[6] = '\0';
}

// Generate unique file ID
void generate_file_id(char *id, const char *prefix) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    snprintf(id, 50, "%s_", prefix);
    int len = strlen(id);
    for (int i = 0; i < 10; i++) {
        id[len + i] = charset[rand() % (sizeof(charset) - 1)];
    }
    id[len + 10] = '\0';
}

// Generate random salt
void generate_salt(char *salt) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 16; i++) {
        salt[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    salt[16] = '\0';
}

// Hash password with salt
void hash_password(const char *password, const char *salt, char *hashed) {
    char combined[200];
    snprintf(combined, sizeof(combined), "%s%s", password, salt);
    
    unsigned long hash = 5381;
    int c;
    const char *str = combined;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    
    snprintf(hashed, 100, "%lu", hash);
}

// Verify password
int verify_password(const char *password, const char *salt, const char *stored_hash) {
    char computed_hash[100];
    hash_password(password, salt, computed_hash);
    return strcmp(computed_hash, stored_hash) == 0;
}

// File locking functions
int lock_file(const char *file_id, const char *username) {
    // Check if file is already locked
    for (int i = 0; i < lock_count; i++) {
        if (strcmp(file_locks[i].file_id, file_id) == 0) {
            if (file_locks[i].is_locked && strcmp(file_locks[i].locked_by, username) != 0) {
                return 0; // File is locked by another user
            } else if (strcmp(file_locks[i].locked_by, username) == 0) {
                // Update lock time for existing lock
                file_locks[i].locked_at = time(NULL);
                return 1;
            }
        }
    }
    
    // Create new lock
    if (lock_count < MAX_LOCKS) {
        strncpy(file_locks[lock_count].file_id, file_id, 49);
        file_locks[lock_count].file_id[49] = '\0';
        strncpy(file_locks[lock_count].locked_by, username, 49);
        file_locks[lock_count].locked_by[49] = '\0';
        file_locks[lock_count].locked_at = time(NULL);
        file_locks[lock_count].is_locked = 1;
        lock_count++;
        return 1;
    }
    
    return 0;
}

int unlock_file(const char *file_id, const char *username) {
    for (int i = 0; i < lock_count; i++) {
        if (strcmp(file_locks[i].file_id, file_id) == 0 && 
            strcmp(file_locks[i].locked_by, username) == 0) {
            file_locks[i].is_locked = 0;
            return 1;
        }
    }
    return 0;
}

int is_file_locked(const char *file_id, char *locked_by) {
    for (int i = 0; i < lock_count; i++) {
        if (strcmp(file_locks[i].file_id, file_id) == 0 && file_locks[i].is_locked) {
            if (time(NULL) - file_locks[i].locked_at > 300) { // 5 minute timeout
                file_locks[i].is_locked = 0; // Auto-unlock after timeout
                return 0;
            }
            if (locked_by) {
                strcpy(locked_by, file_locks[i].locked_by);
            }
            return 1;
        }
    }
    return 0;
}

// User presence tracking
void update_user_presence(const char *username, const char *org_code) {
    time_t now = time(NULL);
    
    for (int i = 0; i < presence_count; i++) {
        if (strcmp(user_presence[i].username, username) == 0 && 
            strcmp(user_presence[i].org_code, org_code) == 0) {
            user_presence[i].last_seen = now;
            user_presence[i].is_online = 1;
            return;
        }
    }
    
    if (presence_count < MAX_PRESENCE) {
        strncpy(user_presence[presence_count].username, username, 49);
        user_presence[presence_count].username[49] = '\0';
        strncpy(user_presence[presence_count].org_code, org_code, 6);
        user_presence[presence_count].org_code[6] = '\0';
        user_presence[presence_count].last_seen = now;
        user_presence[presence_count].is_online = 1;
        presence_count++;
    }
}

void cleanup_old_presence() {
    time_t now = time(NULL);
    for (int i = 0; i < presence_count; i++) {
        if (now - user_presence[i].last_seen > 120) {
            user_presence[i].is_online = 0;
        }
    }
}

// Create users file with demo accounts
void create_default_users() {
    FILE *file = fopen(USER_FILE, "w");
    if (file) {
        printf("Creating new users database: %s\n", USER_FILE);
        fprintf(file, "# User Database (username password_hash salt)\n\n");
        
        char salt[50];
        char hashed[100];
        
        generate_salt(salt);
        hash_password("demo123", salt, hashed);
        fprintf(file, "demo %s %s\n", hashed, salt);
        
        generate_salt(salt);
        hash_password("admin123", salt, hashed);
        fprintf(file, "admin %s %s\n", hashed, salt);
        
        fclose(file);
        printf("Created default users with encrypted passwords.\n");
    } else {
        printf("ERROR: Could not create users file!\n");
    }
}

// Load users from file
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
            char password[100] = {0};
            char salt[50] = {0};
            
            if (sscanf(line, "%49s %99s %49s", username, password, salt) == 3) {
                strcpy(users[user_count].username, username);
                strcpy(users[user_count].password, password);
                strcpy(users[user_count].salt, salt);
                printf("  Loaded user %d: %s\n", user_count + 1, username);
                user_count++;
            }
        }
        fclose(file);
        printf("Total users loaded: %d\n\n", user_count);
        
        if (user_count == 0) {
            create_default_users();
            load_users();
        }
    } else {
        printf("Users file not found. Creating new one...\n");
        create_default_users();
        load_users();
    }
}

// Load organizations from file
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
            memset(&org, 0, sizeof(Organization));
            
            char *token = strtok(line, "|");
            int field = 0;
            
            while (token != NULL) {
                switch (field) {
                    case 0: strncpy(org.code, token, 6); org.code[6] = '\0'; break;
                    case 1: strncpy(org.name, token, 99); org.name[99] = '\0'; break;
                    case 2: strncpy(org.password, token, 99); org.password[99] = '\0'; break;
                    case 3: strncpy(org.salt, token, 49); org.salt[49] = '\0'; break;
                    case 4: strncpy(org.creator, token, 49); org.creator[49] = '\0'; break;
                    case 5: org.member_count = atoi(token); break;
                    default: 
                        if (field - 6 < org.member_count && field - 6 < 50) {
                            strncpy(org.members[field - 6], token, 49);
                            org.members[field - 6][49] = '\0';
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
        file = fopen(ORG_FILE, "w");
        if (file) {
            fprintf(file, "# Organization Database\n");
            fprintf(file, "# Format: code|name|password_hash|salt|creator|member_count|member1|member2|...\n\n");
            fclose(file);
        }
    }
}

// Load files from file
void load_files() {
    FILE *file = fopen(FILES_FILE, "r");
    if (file) {
        file_count = 0;
        char line[8192];
        
        printf("Loading files from %s:\n", FILES_FILE);
        
        while (fgets(line, sizeof(line), file) && file_count < MAX_FILES) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
                continue;
            }
            
            line[strcspn(line, "\r\n")] = 0;
            
            File f;
            memset(&f, 0, sizeof(File));
            
            char *token = strtok(line, "|");
            int field = 0;
            
            while (token != NULL) {
                switch (field) {
                    case 0: strncpy(f.id, token, 49); f.id[49] = '\0'; break;
                    case 1: strncpy(f.filename, token, 99); f.filename[99] = '\0'; break;
                    case 2: strncpy(f.content, token, 8191); f.content[8191] = '\0'; break;
                    case 3: strncpy(f.owner, token, 49); f.owner[49] = '\0'; break;
                    case 4: strncpy(f.org_code, token, 6); f.org_code[6] = '\0'; break;
                    case 5: f.created_at = atol(token); break;
                    case 6: f.modified_at = atol(token); break;
                    case 7: strncpy(f.permissions, token, 19); f.permissions[19] = '\0'; break;
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
            fprintf(file, "# Format: id|filename|content|owner|org_code|created_at|modified_at|permissions\n\n");
            fclose(file);
        }
    }
}

// Load user roles from file
void load_user_roles() {
    FILE *file = fopen(ROLES_FILE, "r");
    if (file) {
        role_count = 0;
        char line[256];
        
        printf("Loading user roles from %s:\n", ROLES_FILE);
        
        while (fgets(line, sizeof(line), file) && role_count < MAX_ROLES) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
            
            line[strcspn(line, "\r\n")] = 0;
            
            char org_code[7] = {0};
            char username[50] = {0};
            char role[20] = {0};
            
            if (sscanf(line, "%6s %49s %19s", org_code, username, role) == 3) {
                strncpy(user_roles[role_count].org_code, org_code, 6);
                user_roles[role_count].org_code[6] = '\0';
                strncpy(user_roles[role_count].username, username, 49);
                user_roles[role_count].username[49] = '\0';
                strncpy(user_roles[role_count].role, role, 19);
                user_roles[role_count].role[19] = '\0';
                printf("  Role: %s in %s -> %s\n", username, org_code, role);
                role_count++;
            }
        }
        fclose(file);
        printf("Total role assignments loaded: %d\n\n", role_count);
    } else {
        printf("Roles file not found. Creating empty database.\n");
        file = fopen(ROLES_FILE, "w");
        if (file) {
            fprintf(file, "# User Roles Database\n# Format: org_code username role\n\n");
            fclose(file);
        }
    }
}

// Save ALL users to file
void save_all_users() {
    FILE *file = fopen(USER_FILE, "w");
    if (file) {
        fprintf(file, "# User Database (username password_hash salt)\n\n");
        
        for (int i = 0; i < user_count; i++) {
            fprintf(file, "%s %s %s\n", users[i].username, users[i].password, users[i].salt);
        }
        fclose(file);
        printf("Saved ALL %d users to %s\n", user_count, USER_FILE);
    } else {
        printf("ERROR: Could not save users to file!\n");
    }
}

// Save ALL organizations to file
void save_all_organizations() {
    FILE *file = fopen(ORG_FILE, "w");
    if (file) {
        fprintf(file, "# Organization Database\n");
        fprintf(file, "# Format: code|name|password_hash|salt|creator|member_count|member1|member2|...\n\n");
        
        for (int i = 0; i < org_count; i++) {
            fprintf(file, "%s|%s|%s|%s|%s|%d", 
                   organizations[i].code,
                   organizations[i].name,
                   organizations[i].password,
                   organizations[i].salt,
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

// Save ALL files to file
void save_all_files() {
    FILE *file = fopen(FILES_FILE, "w");
    if (file) {
        fprintf(file, "# Files Database\n");
        fprintf(file, "# Format: id|filename|content|owner|org_code|created_at|modified_at|permissions\n\n");
        
        for (int i = 0; i < file_count; i++) {
            fprintf(file, "%s|%s|%s|%s|%s|%ld|%ld|%s\n",
                   files[i].id,
                   files[i].filename,
                   files[i].content,
                   files[i].owner,
                   files[i].org_code,
                   (long)files[i].created_at,
                   (long)files[i].modified_at,
                   files[i].permissions);
        }
        fclose(file);
        printf("Saved ALL %d files to %s\n", file_count, FILES_FILE);
    } else {
        printf("ERROR: Could not save files to file!\n");
    }
}

// Save ALL user roles to file
void save_all_roles() {
    FILE *file = fopen(ROLES_FILE, "w");
    if (file) {
        fprintf(file, "# User Roles Database\n# Format: org_code username role\n\n");
        
        for (int i = 0; i < role_count; i++) {
            fprintf(file, "%s %s %s\n", 
                   user_roles[i].org_code,
                   user_roles[i].username,
                   user_roles[i].role);
        }
        fclose(file);
        printf("Saved %d role assignments to %s\n", role_count, ROLES_FILE);
    } else {
        printf("ERROR: Could not save roles to file!\n");
    }
}

// Verify user credentials
int verify_user(const char *username, const char *password) {
    printf("Verifying user: '%s'\n", username);
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            if (verify_password(password, users[i].salt, users[i].password)) {
                printf("  [SUCCESS] User '%s' authenticated\n", username);
                return 1;
            } else {
                printf("  [FAILED] Incorrect password for user '%s'\n", username);
                return 0;
            }
        }
    }
    printf("  [FAILED] User '%s' not found in database\n", username);
    return 0;
}

// Add new user
int add_user(const char *username, const char *password) {
    printf("Adding new user: %s\n", username);
    
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
    
    // Generate salt and hash password
    char salt[50];
    char hashed_password[100];
    
    generate_salt(salt);
    hash_password(password, salt, hashed_password);
    
    // Add user to memory
    strncpy(users[user_count].username, username, 49);
    users[user_count].username[49] = '\0';
    strncpy(users[user_count].password, hashed_password, 99);
    users[user_count].password[99] = '\0';
    strncpy(users[user_count].salt, salt, 49);
    users[user_count].salt[49] = '\0';
    user_count++;
    
    // Create user directory
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "users/%s", username);
    _mkdir("users");
    _mkdir(user_dir);
    
    // Save ALL users to file
    save_all_users();
    
    printf("User '%s' successfully added to database\n", username);
    return 1;
}

// Create new organization with hashed password
int create_organization(const char *org_name, const char *org_password, const char *creator) {
    printf("Creating organization: %s by %s\n", org_name, creator);
    
    if (org_count >= MAX_ORGS) {
        printf("Error: Maximum organization limit reached\n");
        return 0;
    }
    
    // Generate unique organization code
    char org_code[7];
    int unique = 0;
    int attempts = 0;
    while (!unique && attempts < 100) {
        generate_org_code(org_code);
        unique = 1;
        for (int i = 0; i < org_count; i++) {
            if (strcmp(organizations[i].code, org_code) == 0) {
                unique = 0;
                break;
            }
        }
        attempts++;
    }
    
    if (!unique) {
        printf("Error: Could not generate unique organization code\n");
        return 0;
    }
    
    // Hash organization password
    char salt[50];
    char hashed_password[100];
    generate_salt(salt);
    hash_password(org_password, salt, hashed_password);
    
    // Create organization
    Organization org;
    memset(&org, 0, sizeof(Organization));
    strncpy(org.code, org_code, 6);
    org.code[6] = '\0';
    strncpy(org.name, org_name, 99);
    org.name[99] = '\0';
    strncpy(org.password, hashed_password, 99);
    org.password[99] = '\0';
    strncpy(org.salt, salt, 49);
    org.salt[49] = '\0';
    strncpy(org.creator, creator, 49);
    org.creator[49] = '\0';
    org.member_count = 1;
    strncpy(org.members[0], creator, 49);
    org.members[0][49] = '\0';
    
    organizations[org_count] = org;
    org_count++;
    
    // Create organization directory structure
    char org_dir[256];
    snprintf(org_dir, sizeof(org_dir), "organizations/%s", org_code);
    
    // Create directories recursively
    _mkdir("organizations");
    if (_mkdir(org_dir) != 0) {
        // Directory might already exist, which is fine
        printf("Note: Organization directory might already exist: %s\n", org_dir);
    }
    
    // Create subdirectories for better organization
    char sub_dirs[3][50] = {"files", "backups", "shared"};
    for (int i = 0; i < 3; i++) {
        char sub_dir[256];
        snprintf(sub_dir, sizeof(sub_dir), "%s/%s", org_dir, sub_dirs[i]);
        _mkdir(sub_dir);
    }
    
    printf("Organization directory structure created: %s\n", org_dir);
    
    // Set creator as owner in roles
    if (role_count < MAX_ROLES) {
        strncpy(user_roles[role_count].org_code, org_code, 6);
        user_roles[role_count].org_code[6] = '\0';
        strncpy(user_roles[role_count].username, creator, 49);
        user_roles[role_count].username[49] = '\0';
        strncpy(user_roles[role_count].role, "owner", 19);
        user_roles[role_count].role[19] = '\0';
        role_count++;
        save_all_roles();
    }
    
    // Save organizations
    save_all_organizations();
    
    printf("Organization '%s' created with code: %s\n", org_name, org_code);
    return 1;
}

// Create or update file with proper organization folder structure

// Join organization with hashed password verification
int join_organization(const char *org_code, const char *org_password, const char *username) {
    printf("User '%s' attempting to join organization: %s\n", username, org_code);
    
    for (int i = 0; i < org_count; i++) {
        if (strcmp(organizations[i].code, org_code) == 0) {
            // Verify password
            if (!verify_password(org_password, organizations[i].salt, organizations[i].password)) {
                printf("  [FAILED] Invalid organization password\n");
                return 0;
            }
            
            // Check if user is already a member
            for (int j = 0; j < organizations[i].member_count; j++) {
                if (strcmp(organizations[i].members[j], username) == 0) {
                    printf("  [INFO] User already a member of this organization\n");
                    return 1;
                }
            }
            
            // Add user to organization
            if (organizations[i].member_count < 50) {
                strncpy(organizations[i].members[organizations[i].member_count], username, 49);
                organizations[i].members[organizations[i].member_count][49] = '\0';
                organizations[i].member_count++;
                
                // Set default role as spectator
                if (role_count < MAX_ROLES) {
                    strncpy(user_roles[role_count].org_code, org_code, 6);
                    user_roles[role_count].org_code[6] = '\0';
                    strncpy(user_roles[role_count].username, username, 49);
                    user_roles[role_count].username[49] = '\0';
                    strncpy(user_roles[role_count].role, "spectator", 19);
                    user_roles[role_count].role[19] = '\0';
                    role_count++;
                    save_all_roles();
                }
                
                // Save organizations
                save_all_organizations();
                
                printf("  [SUCCESS] User '%s' added to organization '%s'\n", username, organizations[i].name);
                return 1;
            } else {
                printf("  [FAILED] Organization member limit reached\n");
                return 0;
            }
        }
    }
    
    printf("  [FAILED] Organization not found: %s\n", org_code);
    return 0;
}

// Get user role in organization
const char* get_user_role(const char *org_code, const char *username) {
    for (int i = 0; i < role_count; i++) {
        if (strcmp(user_roles[i].org_code, org_code) == 0 && 
            strcmp(user_roles[i].username, username) == 0) {
            return user_roles[i].role;
        }
    }
    return "spectator";
}

// Set user role in organization
int set_user_role(const char *org_code, const char *username, const char *role, const char *requester) {
    const char *requester_role = get_user_role(org_code, requester);
    if (strcmp(requester_role, "owner") != 0) {
        printf("Permission denied: Only owners can set roles\n");
        return 0;
    }
    
    // Find existing role assignment
    for (int i = 0; i < role_count; i++) {
        if (strcmp(user_roles[i].org_code, org_code) == 0 && 
            strcmp(user_roles[i].username, username) == 0) {
            strncpy(user_roles[i].role, role, 19);
            user_roles[i].role[19] = '\0';
            save_all_roles();
            printf("Updated role: %s in %s -> %s\n", username, org_code, role);
            return 1;
        }
    }
    
    // Create new role assignment
    if (role_count < MAX_ROLES) {
        strncpy(user_roles[role_count].org_code, org_code, 6);
        user_roles[role_count].org_code[6] = '\0';
        strncpy(user_roles[role_count].username, username, 49);
        user_roles[role_count].username[49] = '\0';
        strncpy(user_roles[role_count].role, role, 19);
        user_roles[role_count].role[19] = '\0';
        role_count++;
        save_all_roles();
        printf("Set role: %s in %s -> %s\n", username, org_code, role);
        return 1;
    }
    
    return 0;
}

// Check file access permissions
int can_access_file(const char *username, File *file, const char *operation) {
    if (strcmp(file->owner, username) == 0) {
        return 1;
    }
    
    if (strlen(file->org_code) > 0) {
        const char *role = get_user_role(file->org_code, username);
        
        if (strcmp(operation, "read") == 0) {
            return 1;
        } else if (strcmp(operation, "write") == 0) {
            return strcmp(role, "spectator") != 0;
        } else if (strcmp(operation, "delete") == 0) {
            return strcmp(role, "owner") == 0;
        }
    }
    
    return 0;
}

// Create or update file
int create_file(const char *filename, const char *content, const char *owner, const char *org_code) {
    printf("Creating/updating file: %s for user %s in org %s\n", filename, owner, org_code);
    
    // Check if file already exists (update instead of create)
    int existing_index = -1;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filename, filename) == 0 &&
            strcmp(files[i].owner, owner) == 0 &&
            strcmp(files[i].org_code, org_code) == 0) {
            existing_index = i;
            break;
        }
    }
    
    if (existing_index >= 0) {
        // Update existing file
        strncpy(files[existing_index].content, content, 8191);
        files[existing_index].content[8191] = '\0';
        files[existing_index].modified_at = time(NULL);
        printf("Updated existing file: %s (ID: %s)\n", filename, files[existing_index].id);
    } else {
        // Create new file
        if (file_count >= MAX_FILES) {
            printf("Error: Maximum file limit reached\n");
            return 0;
        }
        
        File new_file;
        memset(&new_file, 0, sizeof(File));
        generate_file_id(new_file.id, "file");
        strncpy(new_file.filename, filename, 99);
        new_file.filename[99] = '\0';
        strncpy(new_file.content, content, 8191);
        new_file.content[8191] = '\0';
        strncpy(new_file.owner, owner, 49);
        new_file.owner[49] = '\0';
        strncpy(new_file.org_code, org_code, 6);
        new_file.org_code[6] = '\0';
        new_file.created_at = time(NULL);
        new_file.modified_at = time(NULL);
        strncpy(new_file.permissions, "private", 19);
        new_file.permissions[19] = '\0';
        
        files[file_count] = new_file;
        existing_index = file_count;
        file_count++;
        printf("Created new file: %s (ID: %s)\n", filename, new_file.id);
    }
    
    // Save file to user directory
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "users/%s", owner);
    _mkdir("users");
    _mkdir(user_dir);
    
    char user_file_path[512];
    snprintf(user_file_path, sizeof(user_file_path), "users/%s/%s.txt", owner, files[existing_index].id);
    FILE *user_file = fopen(user_file_path, "w");
    if (user_file) {
        fprintf(user_file, "ID:%s\nFILENAME:%s\nOWNER:%s\nORG:%s\nCREATED:%ld\nMODIFIED:%ld\nPERMISSIONS:%s\n\nCONTENT:\n%s",
                files[existing_index].id, filename, owner, org_code, 
                (long)files[existing_index].created_at, (long)files[existing_index].modified_at, 
                files[existing_index].permissions, content);
        fclose(user_file);
    }
    
    // Save file to organization directory if applicable
    if (strlen(org_code) > 0) {
        char org_dir[256];
        snprintf(org_dir, sizeof(org_dir), "organizations/%s", org_code);
        _mkdir("organizations");
        _mkdir(org_dir);
        
        char org_file_path[512];
        snprintf(org_file_path, sizeof(org_file_path), "organizations/%s/%s.txt", org_code, files[existing_index].id);
        FILE *org_file = fopen(org_file_path, "w");
        if (org_file) {
            fprintf(org_file, "ID:%s\nFILENAME:%s\nOWNER:%s\nORG:%s\nCREATED:%ld\nMODIFIED:%ld\nPERMISSIONS:%s\n\nCONTENT:\n%s",
                    files[existing_index].id, filename, owner, org_code, 
                    (long)files[existing_index].created_at, (long)files[existing_index].modified_at, 
                    files[existing_index].permissions, content);
            fclose(org_file);
        }
    }
    
    save_all_files();
    return 1;
}

// Sync personal file to organization with proper folder structure
int sync_file_to_org(const char *file_id, const char *org_code, const char *username) {
    printf("Syncing file %s to organization %s for user %s\n", file_id, org_code, username);
    
    // Find the personal file
    File *personal_file = NULL;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].id, file_id) == 0 && 
            strcmp(files[i].owner, username) == 0 &&
            strlen(files[i].org_code) == 0) {
            personal_file = &files[i];
            break;
        }
    }
    
    if (!personal_file) {
        printf("Error: Personal file not found or not owned by user\n");
        return 0;
    }
    
    // Check if user has permission to write to organization
    const char *role = get_user_role(org_code, username);
    if (strcmp(role, "spectator") == 0) {
        printf("Error: Spectators cannot sync files to organization\n");
        return 0;
    }
    
    // Create organization version of the file
    File org_file;
    memset(&org_file, 0, sizeof(File));
    generate_file_id(org_file.id, "org_file");
    strncpy(org_file.filename, personal_file->filename, 99);
    org_file.filename[99] = '\0';
    strncpy(org_file.content, personal_file->content, 8191);
    org_file.content[8191] = '\0';
    strncpy(org_file.owner, username, 49);
    org_file.owner[49] = '\0';
    strncpy(org_file.org_code, org_code, 6);
    org_file.org_code[6] = '\0';
    org_file.created_at = time(NULL);
    org_file.modified_at = time(NULL);
    strncpy(org_file.permissions, "shared", 19);
    org_file.permissions[19] = '\0';
    
    if (file_count < MAX_FILES) {
        files[file_count] = org_file;
        file_count++;
        
        // Save to organization folder structure
        char org_dir[256];
        snprintf(org_dir, sizeof(org_dir), "organizations/%s/files", org_code);
        _mkdir("organizations");
        _mkdir(org_dir);
        
        char org_file_path[512];
        snprintf(org_file_path, sizeof(org_file_path), "%s/%s.txt", org_dir, org_file.id);
        FILE *org_file_ptr = fopen(org_file_path, "w");
        if (org_file_ptr) {
            fprintf(org_file_ptr, "ID:%s\nFILENAME:%s\nOWNER:%s\nORG:%s\nCREATED:%ld\nMODIFIED:%ld\nPERMISSIONS:%s\n\nCONTENT:\n%s",
                    org_file.id, org_file.filename, org_file.owner, org_file.org_code, 
                    (long)org_file.created_at, (long)org_file.modified_at, 
                    org_file.permissions, org_file.content);
            fclose(org_file_ptr);
            printf("File synced to organization folder: %s\n", org_file_path);
        } else {
            printf("Error: Could not save synced file to organization folder\n");
        }
        
        save_all_files();
        printf("File synced to organization successfully\n");
        return 1;
    }
    
    printf("Error: Maximum file limit reached\n");
    return 0;
}

// Get files for user/organization
int get_user_files(const char *username, const char *org_code, File *result_files, int max_results) {
    int count = 0;
    
    for (int i = 0; i < file_count && count < max_results; i++) {
        if ((strlen(org_code) == 0 && strlen(files[i].org_code) == 0 && strcmp(files[i].owner, username) == 0) ||
            (strlen(org_code) > 0 && strcmp(files[i].org_code, org_code) == 0)) {
            
            if (strlen(org_code) > 0 && !can_access_file(username, &files[i], "read")) {
                continue;
            }
            
            result_files[count] = files[i];
            count++;
        }
    }
    
    return count;
}

// Search files
int search_files(const char *query, const char *username, const char *org_code, File *result_files, int max_results) {
    int count = 0;
    
    for (int i = 0; i < file_count && count < max_results; i++) {
        // Check if file matches search criteria
        int matches = 0;
        
        if (strstr(files[i].filename, query) != NULL) {
            matches = 1;
        } else if (strstr(files[i].content, query) != NULL) {
            matches = 1;
        }
        
        if (matches) {
            // Check permissions
            if (strlen(org_code) > 0) {
                if (strcmp(files[i].org_code, org_code) == 0 && can_access_file(username, &files[i], "read")) {
                    result_files[count] = files[i];
                    count++;
                }
            } else {
                if (strlen(files[i].org_code) == 0 && strcmp(files[i].owner, username) == 0) {
                    result_files[count] = files[i];
                    count++;
                }
            }
        }
    }
    
    return count;
}

// Get organization by code
Organization* get_organization(const char *org_code) {
    for (int i = 0; i < org_count; i++) {
        if (strcmp(organizations[i].code, org_code) == 0) {
            return &organizations[i];
        }
    }
    return NULL;
}

// Get all users for role management
int get_all_users(User *result_users, int max_results) {
    int count = 0;
    for (int i = 0; i < user_count && count < max_results; i++) {
        result_users[count] = users[i];
        count++;
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

// Parse form data safely
void parse_form_field(const char *data, const char *field_name, char *output, int max_len) {
    char search_str[100];
    snprintf(search_str, sizeof(search_str), "%s=", field_name);
    
    const char *start = strstr(data, search_str);
    if (!start) {
        output[0] = '\0';
        return;
    }
    
    start += strlen(search_str);
    const char *end = strchr(start, '&');
    int len = end ? (int)(end - start) : strlen(start);
    
    if (len >= max_len) len = max_len - 1;
    
    strncpy(output, start, len);
    output[len] = '\0';
    url_decode(output);
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

// Create response with organization code
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

// Create response with organization info
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

// Create response with files data
char* create_files_response(int status, File *result_files, int count) {
    static char response[MAX_BUFFER_SIZE];
    const char *status_text = status == 200 ? "OK" : "Bad Request";
    
    char *files_json = (char*)malloc(8192);
    if (!files_json) {
        return create_response(500, "Memory allocation failed");
    }
    
    files_json[0] = '\0';
    for (int i = 0; i < count && i < 20; i++) {
        char file_json[512];
        snprintf(file_json, sizeof(file_json),
            "%s{\"id\":\"%s\",\"filename\":\"%s\",\"owner\":\"%s\",\"org_code\":\"%s\",\"created_at\":%ld,\"modified_at\":%ld}",
            i > 0 ? "," : "", result_files[i].id, result_files[i].filename, 
            result_files[i].owner, result_files[i].org_code, 
            (long)result_files[i].created_at, (long)result_files[i].modified_at);
        strncat(files_json, file_json, 8191 - strlen(files_json));
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
    
    free(files_json);
    return response;
}

// Create response with role info
char* create_role_response(int status, const char *message, const char *role) {
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
        "{\"status\":\"%s\",\"message\":\"%s\",\"role\":\"%s\"}",
        status, status_text, status == 200 ? "success" : "error", message, role);
    
    return response;
}

// Create response with online users
char* create_online_users_response(int status, UserPresenceRecord *online_users, int count) {
    static char response[MAX_BUFFER_SIZE];
    const char *status_text = status == 200 ? "OK" : "Bad Request";
    
    char *users_json = (char*)malloc(8192);
    if (!users_json) {
        return create_response(500, "Memory allocation failed");
    }
    
    users_json[0] = '\0';
    for (int i = 0; i < count && i < 50; i++) {
        char user_json[256];
        snprintf(user_json, sizeof(user_json),
            "%s{\"username\":\"%s\",\"last_seen\":%ld,\"is_online\":%d}",
            i > 0 ? "," : "", online_users[i].username, 
            (long)online_users[i].last_seen, online_users[i].is_online);
        strncat(users_json, user_json, 8191 - strlen(users_json));
    }
    
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"%s\",\"users\":[%s]}",
        status, status_text, status == 200 ? "success" : "error", users_json);
    
    free(users_json);
    return response;
}

// Create response with file lock info
char* create_lock_response(int status, const char *message, const char *locked_by) {
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
        "{\"status\":\"%s\",\"message\":\"%s\",\"locked_by\":\"%s\"}",
        status, status_text, status == 200 ? "success" : "error", message, locked_by ? locked_by : "");
    
    return response;
}

// Create response with all users for role management
char* create_all_users_response(int status, User *users, int count) {
    static char response[MAX_BUFFER_SIZE];
    const char *status_text = status == 200 ? "OK" : "Bad Request";
    
    char *users_json = (char*)malloc(8192);
    if (!users_json) {
        return create_response(500, "Memory allocation failed");
    }
    
    users_json[0] = '\0';
    for (int i = 0; i < count && i < 100; i++) {
        char user_json[256];
        snprintf(user_json, sizeof(user_json),
            "%s{\"username\":\"%s\"}",
            i > 0 ? "," : "", users[i].username);
        strncat(users_json, user_json, 8191 - strlen(users_json));
    }
    
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"status\":\"%s\",\"users\":[%s]}",
        status, status_text, status == 200 ? "success" : "error", users_json);
    
    free(users_json);
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
        
        if (file_size > 0 && file_size < 1000000) {
            char *file_content = (char*)malloc(file_size + 1);
            if (file_content) {
                size_t read_size = fread(file_content, 1, file_size, file);
                file_content[read_size] = '\0';
                
                char header[512];
                snprintf(header, sizeof(header),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %ld\r\n"
                    "Connection: close\r\n"
                    "\r\n", file_size);
                
                send(client_socket, header, strlen(header), 0);
                send(client_socket, file_content, read_size, 0);
                
                free(file_content);
            }
        }
        fclose(file);
    } else {
        printf("ERROR: Could not open file %s\n", filename);
        const char *response = 
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<h1>404 - File Not Found</h1>";
        send(client_socket, response, strlen(response), 0);
    }
}

int main() {
    WSADATA wsa;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server, client;
    int client_len = sizeof(struct sockaddr_in);
    
    srand((unsigned int)time(NULL));
    
    printf("=== Text Editor with Organizations Server ===\n");
    printf("Initializing databases...\n");
    load_users();
    load_organizations();
    load_files();
    load_user_roles();
    
    _mkdir("users");
    _mkdir("organizations");
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    
    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    if (listen(server_socket, 3) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Server running on port %d\n", PORT);
    printf("Available URLs:\n");
    printf("  http://localhost:%d/\n", PORT);
    printf("  http://localhost:%d/login\n", PORT);
    printf("  http://localhost:%d/dashboard\n", PORT);
    printf("  http://localhost:%d/editor\n", PORT);
    printf("\nReady to accept connections...\n\n");
    
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        char *buffer = (char*)malloc(MAX_BUFFER_SIZE);
        if (!buffer) {
            closesocket(client_socket);
            continue;
        }
        
        memset(buffer, 0, MAX_BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, MAX_BUFFER_SIZE - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            if (strstr(buffer, "GET / ") || strstr(buffer, "GET /start")) {
                printf("[GET] Serving start page\n");
                serve_html_file(client_socket, "start.html");
            }
            else if (strstr(buffer, "GET /dashboard")) {
                printf("[GET] Serving dashboard\n");
                serve_html_file(client_socket, "dashboard.html");
            }
            else if (strstr(buffer, "GET /login")) {
                printf("[GET] Serving login page\n");
                serve_html_file(client_socket, "login.html");
            }
            else if (strstr(buffer, "GET /create_org")) {
                printf("[GET] Serving create organization page\n");
                serve_html_file(client_socket, "create_org.html");
            }
            else if (strstr(buffer, "GET /org_login")) {
                printf("[GET] Serving organization login page\n");
                serve_html_file(client_socket, "org_login.html");
            }
            else if (strstr(buffer, "GET /editor")) {
                printf("[GET] Serving editor page\n");
                serve_html_file(client_socket, "editor.html");
            }
            else if (strstr(buffer, "GET /org_management")) {
                printf("[GET] Serving organization management page\n");
                serve_html_file(client_socket, "org_management.html");
            }
            else if (strstr(buffer, "POST /create_org")) {
                printf("[POST] Processing organization creation\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char org_name[100] = {0};
                    char org_password[50] = {0};
                    char username[50] = {0};
                    
                    parse_form_field(body, "orgName", org_name, sizeof(org_name));
                    parse_form_field(body, "orgPassword", org_password, sizeof(org_password));
                    parse_form_field(body, "username", username, sizeof(username));
                    
                    if (strlen(org_name) < 2) {
                        char *response = create_response(400, "Organization name too short");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(org_password) < 4) {
                        char *response = create_response(400, "Password too short");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        if (create_organization(org_name, org_password, username)) {
                            for (int i = 0; i < org_count; i++) {
                                if (strcmp(organizations[i].creator, username) == 0 && 
                                    strcmp(organizations[i].name, org_name) == 0) {
                                    char *response = create_org_response(200, "Organization created", organizations[i].code);
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
            else if (strstr(buffer, "POST /join_org")) {
                printf("[POST] Processing organization join\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char org_code[7] = {0};
                    char org_password[50] = {0};
                    char username[50] = {0};
                    
                    parse_form_field(body, "orgCode", org_code, sizeof(org_code));
                    parse_form_field(body, "orgPassword", org_password, sizeof(org_password));
                    parse_form_field(body, "username", username, sizeof(username));
                    
                    if (strlen(org_code) != 6) {
                        char *response = create_response(400, "Invalid organization code");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        if (join_organization(org_code, org_password, username)) {
                            Organization *org = get_organization(org_code);
                            if (org) {
                                char *response = create_join_org_response(200, "Successfully joined", org->name);
                                send(client_socket, response, strlen(response), 0);
                            }
                        } else {
                            char *response = create_response(400, "Invalid code or password");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            else if (strstr(buffer, "POST /create_file")) {
                printf("[POST] Processing file creation\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char filename[100] = {0};
                    char *content = (char*)malloc(8192);
                    char owner[50] = {0};
                    char org_code[7] = {0};
                    
                    if (content) {
                        parse_form_field(body, "filename", filename, sizeof(filename));
                        parse_form_field(body, "content", content, 8192);
                        parse_form_field(body, "owner", owner, sizeof(owner));
                        parse_form_field(body, "orgCode", org_code, sizeof(org_code));
                        
                        if (strlen(filename) == 0) {
                            char *response = create_response(400, "Filename required");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            if (strlen(org_code) > 0) {
                                const char *role = get_user_role(org_code, owner);
                                if (strcmp(role, "spectator") == 0) {
                                    char *response = create_response(403, "Spectators cannot create files");
                                    send(client_socket, response, strlen(response), 0);
                                    free(content);
                                    closesocket(client_socket);
                                    free(buffer);
                                    continue;
                                }
                            }
                            
                            if (create_file(filename, content, owner, org_code)) {
                                char *response = create_response(200, "File saved successfully");
                                send(client_socket, response, strlen(response), 0);
                            } else {
                                char *response = create_response(400, "Failed to save file");
                                send(client_socket, response, strlen(response), 0);
                            }
                        }
                        free(content);
                    }
                }
            }
            else if (strstr(buffer, "POST /sync_file")) {
                printf("[POST] Syncing file to organization\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char file_id[50] = {0};
                    char org_code[7] = {0};
                    char username[50] = {0};
                    
                    parse_form_field(body, "fileId", file_id, sizeof(file_id));
                    parse_form_field(body, "orgCode", org_code, sizeof(org_code));
                    parse_form_field(body, "username", username, sizeof(username));
                    
                    if (strlen(file_id) == 0 || strlen(org_code) == 0 || strlen(username) == 0) {
                        char *response = create_response(400, "Missing required fields");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        if (sync_file_to_org(file_id, org_code, username)) {
                            char *response = create_response(200, "File synced to organization");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_response(400, "Failed to sync file");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            else if (strstr(buffer, "GET /get_files")) {
                printf("[GET] Processing get files\n");
                
                char *query = strstr(buffer, "?");
                if (query) {
                    char username[50] = {0};
                    char org_code[7] = {0};
                    
                    parse_form_field(query + 1, "user", username, sizeof(username));
                    parse_form_field(query + 1, "org", org_code, sizeof(org_code));
                    
                    File *result_files = (File*)malloc(sizeof(File) * 100);
                    if (result_files) {
                        int count = get_user_files(username, org_code, result_files, 100);
                        char *response = create_files_response(200, result_files, count);
                        send(client_socket, response, strlen(response), 0);
                        free(result_files);
                    }
                }
            }
            else if (strstr(buffer, "GET /search_files")) {
                printf("[GET] Searching files\n");
                
                char *query = strstr(buffer, "?");
                if (query) {
                    char search_query[100] = {0};
                    char username[50] = {0};
                    char org_code[7] = {0};
                    
                    parse_form_field(query + 1, "q", search_query, sizeof(search_query));
                    parse_form_field(query + 1, "user", username, sizeof(username));
                    parse_form_field(query + 1, "org", org_code, sizeof(org_code));
                    
                    if (strlen(search_query) > 0) {
                        File *result_files = (File*)malloc(sizeof(File) * 50);
                        if (result_files) {
                            int count = search_files(search_query, username, org_code, result_files, 50);
                            char *response = create_files_response(200, result_files, count);
                            send(client_socket, response, strlen(response), 0);
                            free(result_files);
                        }
                    } else {
                        char *response = create_response(400, "Search query required");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "GET /get_role")) {
                printf("[GET] Processing get role\n");
                
                char *query = strstr(buffer, "?");
                if (query) {
                    char username[50] = {0};
                    char org_code[7] = {0};
                    
                    parse_form_field(query + 1, "user", username, sizeof(username));
                    parse_form_field(query + 1, "org", org_code, sizeof(org_code));
                    
                    const char *role = get_user_role(org_code, username);
                    char *response = create_role_response(200, "Role retrieved", role);
                    send(client_socket, response, strlen(response), 0);
                }
            }
            else if (strstr(buffer, "POST /set_role")) {
                printf("[POST] Processing set role\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char org_code[7] = {0};
                    char username[50] = {0};
                    char role[20] = {0};
                    char requester[50] = {0};
                    
                    parse_form_field(body, "orgCode", org_code, sizeof(org_code));
                    parse_form_field(body, "username", username, sizeof(username));
                    parse_form_field(body, "role", role, sizeof(role));
                    parse_form_field(body, "requester", requester, sizeof(requester));
                    
                    if (set_user_role(org_code, username, role, requester)) {
                        char *response = create_response(200, "Role updated");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        char *response = create_response(400, "Failed to update role");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "GET /get_all_users")) {
                printf("[GET] Getting all users for role management\n");
                
                User *all_users = (User*)malloc(sizeof(User) * 100);
                if (all_users) {
                    int count = get_all_users(all_users, 100);
                    char *response = create_all_users_response(200, all_users, count);
                    send(client_socket, response, strlen(response), 0);
                    free(all_users);
                }
            }
            else if (strstr(buffer, "POST /lock_file")) {
                printf("[POST] Locking file\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char file_id[50] = {0};
                    char username[50] = {0};
                    
                    parse_form_field(body, "fileId", file_id, sizeof(file_id));
                    parse_form_field(body, "username", username, sizeof(username));
                    
                    if (strlen(file_id) > 0 && strlen(username) > 0) {
                        if (lock_file(file_id, username)) {
                            char *response = create_response(200, "File locked");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char locked_by[50] = {0};
                            is_file_locked(file_id, locked_by);
                            char *response = create_lock_response(400, "File is already locked", locked_by);
                            send(client_socket, response, strlen(response), 0);
                        }
                    } else {
                        char *response = create_response(400, "Missing fileId or username");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "POST /unlock_file")) {
                printf("[POST] Unlocking file\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char file_id[50] = {0};
                    char username[50] = {0};
                    
                    parse_form_field(body, "fileId", file_id, sizeof(file_id));
                    parse_form_field(body, "username", username, sizeof(username));
                    
                    if (strlen(file_id) > 0 && strlen(username) > 0) {
                        if (unlock_file(file_id, username)) {
                            char *response = create_response(200, "File unlocked");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_response(400, "File not locked by user");
                            send(client_socket, response, strlen(response), 0);
                        }
                    } else {
                        char *response = create_response(400, "Missing fileId or username");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "GET /check_lock")) {
                printf("[GET] Checking file lock\n");
                
                char *query = strstr(buffer, "?");
                if (query) {
                    char file_id[50] = {0};
                    parse_form_field(query + 1, "fileId", file_id, sizeof(file_id));
                    
                    if (strlen(file_id) > 0) {
                        char locked_by[50] = {0};
                        if (is_file_locked(file_id, locked_by)) {
                            char *response = create_lock_response(200, "File is locked", locked_by);
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_lock_response(200, "File is not locked", "");
                            send(client_socket, response, strlen(response), 0);
                        }
                    } else {
                        char *response = create_response(400, "Missing fileId");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "POST /login")) {
                printf("[POST] Processing login\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char password[50] = {0};
                    
                    parse_form_field(body, "username", username, sizeof(username));
                    parse_form_field(body, "password", password, sizeof(password));
                    
                    if (verify_user(username, password)) {
                        char *response = create_response(200, "Login successful");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        char *response = create_response(400, "Invalid credentials");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "POST /signup")) {
                printf("[POST] Processing signup\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char password[50] = {0};
                    
                    parse_form_field(body, "username", username, sizeof(username));
                    parse_form_field(body, "password", password, sizeof(password));
                    
                    if (strlen(username) < 3) {
                        char *response = create_response(400, "Username too short");
                        send(client_socket, response, strlen(response), 0);
                    } else if (strlen(password) < 8) {
                        char *response = create_response(400, "Password too short");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        if (add_user(username, password)) {
                            char *response = create_response(200, "Account created");
                            send(client_socket, response, strlen(response), 0);
                        } else {
                            char *response = create_response(400, "Username exists");
                            send(client_socket, response, strlen(response), 0);
                        }
                    }
                }
            }
            else if (strstr(buffer, "POST /update_presence")) {
                printf("[POST] Updating user presence\n");
                
                char *body = strstr(buffer, "\r\n\r\n");
                if (body) {
                    body += 4;
                    
                    char username[50] = {0};
                    char org_code[7] = {0};
                    
                    parse_form_field(body, "username", username, sizeof(username));
                    parse_form_field(body, "orgCode", org_code, sizeof(org_code));
                    
                    if (strlen(username) > 0 && strlen(org_code) > 0) {
                        update_user_presence(username, org_code);
                        char *response = create_response(200, "Presence updated");
                        send(client_socket, response, strlen(response), 0);
                    } else {
                        char *response = create_response(400, "Missing username or orgCode");
                        send(client_socket, response, strlen(response), 0);
                    }
                }
            }
            else if (strstr(buffer, "GET /get_online_users")) {
                printf("[GET] Getting online users\n");
                
                char *query = strstr(buffer, "?");
                if (query) {
                    char org_code[7] = {0};
                    parse_form_field(query + 1, "org", org_code, sizeof(org_code));
                    
                    cleanup_old_presence();
                    
                    int online_count = 0;
                    UserPresenceRecord online_users[50];
                    
                    for (int i = 0; i < presence_count && online_count < 50; i++) {
                        if (strcmp(user_presence[i].org_code, org_code) == 0 && 
                            user_presence[i].is_online) {
                            online_users[online_count] = user_presence[i];
                            online_count++;
                        }
                    }
                    
                    char *response = create_online_users_response(200, online_users, online_count);
                    send(client_socket, response, strlen(response), 0);
                }
            }
            else if (strstr(buffer, "OPTIONS")) {
                printf("[OPTIONS] CORS preflight\n");
                const char *response = 
                    "HTTP/1.1 200 OK\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    "Access-Control-Allow-Headers: Content-Type\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(client_socket, response, strlen(response), 0);
            }
            else {
                printf("[UNKNOWN] Serving start page\n");
                serve_html_file(client_socket, "start.html");
            }
        }
        
        closesocket(client_socket);
        free(buffer);
        printf("--- Request completed ---\n\n");
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
}