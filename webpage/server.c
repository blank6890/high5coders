#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define MAX_USERS 1000
#define MAX_USERNAME_LEN 50
#define MAX_EMAIL_LEN 100
#define MAX_PASSWORD_LEN 64
#define USER_DATA_FILE "users.dat"
#define BACKUP_FILE "users.backup"

typedef struct {
    int id;
    char username[MAX_USERNAME_LEN];
    char email[MAX_EMAIL_LEN];
    char password_hash[MAX_PASSWORD_LEN];
    time_t created_at;
    time_t last_login;
    int is_active;
} User;

typedef struct {
    User users[MAX_USERS];
    int count;
} UserDatabase;

// Enhanced function prototypes
int is_valid_email(const char *email);
int is_valid_username(const char *username);
void create_backup();
int restore_backup();

// Email validation
int is_valid_email(const char *email) {
    int at_count = 0;
    int dot_after_at = 0;
    
    for (int i = 0; email[i] != '\0'; i++) {
        if (email[i] == '@') {
            at_count++;
            if (at_count > 1) return 0;
        }
        if (at_count == 1 && email[i] == '.') {
            dot_after_at = 1;
        }
    }
    
    return (at_count == 1 && dot_after_at && strlen(email) >= 5);
}

// Username validation
int is_valid_username(const char *username) {
    if (strlen(username) < 3 || strlen(username) >= MAX_USERNAME_LEN) {
        return 0;
    }
    
    // Check if first character is alphabetic
    if (!isalpha(username[0])) {
        return 0;
    }
    
    // Check if all characters are alphanumeric or underscore
    for (int i = 0; username[i] != '\0'; i++) {
        if (!isalnum(username[i]) && username[i] != '_') {
            return 0;
        }
    }
    
    return 1;
}

// Create backup
void create_backup() {
    FILE *source = fopen(USER_DATA_FILE, "rb");
    FILE *backup = fopen(BACKUP_FILE, "wb");
    
    if (source && backup) {
        char buffer[1024];
        size_t bytes;
        
        while ((bytes = fread(buffer, 1, sizeof(buffer), source)) > 0) {
            fwrite(buffer, 1, bytes, backup);
        }
        
        printf("Backup created successfully.\n");
    }
    
    if (source) fclose(source);
    if (backup) fclose(backup);
}

// Restore from backup
int restore_backup() {
    FILE *backup = fopen(BACKUP_FILE, "rb");
    FILE *target = fopen(USER_DATA_FILE, "wb");
    
    if (!backup) {
        printf("No backup file found.\n");
        return -1;
    }
    
    if (backup && target) {
        char buffer[1024];
        size_t bytes;
        
        while ((bytes = fread(buffer, 1, sizeof(buffer), backup)) > 0) {
            fwrite(buffer, 1, bytes, target);
        }
        
        printf("Backup restored successfully.\n");
        fclose(backup);
        fclose(target);
        return 0;
    }
    
    if (backup) fclose(backup);
    if (target) fclose(target);
    return -1;
}

// Enhanced save_user with validation
int save_user(UserDatabase *db, const char *username, const char *email, const char *password) {
    if (db->count >= MAX_USERS) {
        printf("Error: Database is full!\n");
        return -1;
    }
    
    // Validate username
    if (!is_valid_username(username)) {
        printf("Error: Invalid username! Must be 3-50 characters, start with a letter, and contain only letters, numbers, and underscores.\n");
        return -1;
    }
    
    // Validate email
    if (!is_valid_email(email)) {
        printf("Error: Invalid email format!\n");
        return -1;
    }
    
    // Validate password length
    if (strlen(password) < 6) {
        printf("Error: Password must be at least 6 characters long!\n");
        return -1;
    }
    
    // Check if username already exists
    if (find_user_by_username(db, username) != NULL) {
        printf("Error: Username already exists!\n");
        return -1;
    }
    
    // Check if email already exists
    if (find_user_by_email(db, email) != NULL) {
        printf("Error: Email already exists!\n");
        return -1;
    }
    
    User *new_user = &db->users[db->count];
    
    new_user->id = db->count + 1;
    strncpy(new_user->username, username, MAX_USERNAME_LEN - 1);
    strncpy(new_user->email, email, MAX_EMAIL_LEN - 1);
    
    // Hash the password before storing
    simple_hash(password, new_user->password_hash);
    
    new_user->created_at = time(NULL);
    new_user->last_login = 0;
    new_user->is_active = 1;
    
    db->count++;
    printf("User '%s' created successfully with ID: %d\n", username, new_user->id);
    return new_user->id;
}

// Interactive menu system
void interactive_menu() {
    UserDatabase db;
    init_database(&db);
    load_database(&db);
    
    int choice;
    char username[MAX_USERNAME_LEN];
    char email[MAX_EMAIL_LEN];
    char password[MAX_PASSWORD_LEN];
    
    do {
        printf("\n=== Text Editor User Management ===\n");
        printf("1. Register New User\n");
        printf("2. Login\n");
        printf("3. List All Users\n");
        printf("4. Find User\n");
        printf("5. Delete User\n");
        printf("6. Create Backup\n");
        printf("7. Restore Backup\n");
        printf("8. Save & Exit\n");
        printf("Choose an option: ");
        
        scanf("%d", &choice);
        getchar(); // Clear newline
        
        switch (choice) {
            case 1:
                printf("Enter username: ");
                fgets(username, MAX_USERNAME_LEN, stdin);
                username[strcspn(username, "\n")] = 0;
                
                printf("Enter email: ");
                fgets(email, MAX_EMAIL_LEN, stdin);
                email[strcspn(email, "\n")] = 0;
                
                printf("Enter password: ");
                fgets(password, MAX_PASSWORD_LEN, stdin);
                password[strcspn(password, "\n")] = 0;
                
                save_user(&db, username, email, password);
                break;
                
            case 2:
                printf("Enter username: ");
                fgets(username, MAX_USERNAME_LEN, stdin);
                username[strcspn(username, "\n")] = 0;
                
                printf("Enter password: ");
                fgets(password, MAX_PASSWORD_LEN, stdin);
                password[strcspn(password, "\n")] = 0;
                
                if (authenticate_user(&db, username, password)) {
                    printf("Login successful! Welcome back, %s!\n", username);
                } else {
                    printf("Login failed! Invalid username or password.\n");
                }
                break;
                
            case 3:
                list_all_users(&db);
                break;
                
            case 4:
                printf("Enter username to find: ");
                fgets(username, MAX_USERNAME_LEN, stdin);
                username[strcspn(username, "\n")] = 0;
                
                User *user = find_user_by_username(&db, username);
                print_user(user);
                break;
                
            case 5:
                printf("Enter username to delete: ");
                fgets(username, MAX_USERNAME_LEN, stdin);
                username[strcspn(username, "\n")] = 0;
                
                delete_user(&db, username);
                break;
                
            case 6:
                create_backup();
                break;
                
            case 7:
                restore_backup();
                load_database(&db); // Reload database after restore
                break;
                
            case 8:
                save_database(&db);
                printf("Goodbye!\n");
                break;
                
            default:
                printf("Invalid choice! Please try again.\n");
        }
    } while (choice != 8);
}

int main() {
    printf("=== Text Editor User Management System ===\n");
    
    // Uncomment the line below for demo mode
    // demo();
    
    // Use interactive menu for real usage
    interactive_menu();
    
    return 0;
}