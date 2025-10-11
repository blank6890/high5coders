#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")

#define ID_EDITOR 1001
#define ID_USERS_LIST 1002
#define ID_CHAT_EDIT 1003
#define ID_CHAT_SEND 1004
#define ID_CHAT_DISPLAY 1005
#define ID_CONNECT_BUTTON 1006
#define ID_DISCONNECT_BUTTON 1007
#define ID_STATS_LABEL 1008
#define ID_AUTH_FRAME 1009
#define ID_USERNAME_EDIT 1010
#define ID_PASSWORD_EDIT 1011
#define ID_LOGIN_BUTTON 1012
#define ID_MAIN_FRAME 1013
#define ID_SYNC_BUTTON 1014
#define ID_LOCK_BUTTON 1015
#define ID_UNLOCK_BUTTON 1016

#define PORT 8080
#define BUFFER_SIZE 8192

// Global variables
SOCKET client_socket = INVALID_SOCKET;
HWND hMainWindow, hEditor, hUsersList, hChatEdit, hChatDisplay, hStatsLabel;
HWND hAuthFrame, hUsernameEdit, hPasswordEdit, hLoginButton;
HWND hConnectButton, hDisconnectButton, hSyncButton, hLockButton, hUnlockButton;
int is_connected = 0;
int is_authenticated = 0;
char username[50] = "";
char password[50] = "password123"; // Default password for demo
HANDLE hReceiveThread = NULL;
CRITICAL_SECTION editor_cs;

// Function declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL InitializeWindow(HINSTANCE hInstance);
DWORD WINAPI ReceiveMessages(LPVOID lpParam);
void ConnectToServer();
void DisconnectFromServer();
void SendChatMessage();
void UpdateUsersList(const char* userData);
void UpdateDocument(const char* documentContent);
void UpdateStats(const char* stats);
void ShowAuthPanel(BOOL show);
void LoginUser();
void SendSyncRequest();
void SendLockRequest();
void SendUnlockRequest();
void SendCursorPosition();
void AddChatMessage(const char* username, const char* message);

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBox(NULL, "WSAStartup failed", "Error", MB_ICONERROR);
        return 1;
    }

    // Initialize critical section
    InitializeCriticalSection(&editor_cs);

    // Create and show window
    if (!InitializeWindow(hInstance)) {
        MessageBox(NULL, "Window creation failed", "Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);

    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    WSACleanup();
    DeleteCriticalSection(&editor_cs);

    return (int)msg.wParam;
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            // Create authentication panel
            hAuthFrame = CreateWindowEx(0, "STATIC", "Collaborative Editor Login", 
                                       WS_CHILD | WS_VISIBLE | SS_CENTER | WS_BORDER,
                                       200, 100, 400, 300, hwnd, (HMENU)ID_AUTH_FRAME, 
                                       NULL, NULL);

            CreateWindowEx(0, "STATIC", "Username:", 
                          WS_CHILD | WS_VISIBLE | SS_RIGHT,
                          250, 160, 80, 20, hwnd, NULL, NULL, NULL);
            hUsernameEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "user1", 
                                         WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                         340, 160, 150, 25, hwnd, (HMENU)ID_USERNAME_EDIT, 
                                         NULL, NULL);

            CreateWindowEx(0, "STATIC", "Password:", 
                          WS_CHILD | WS_VISIBLE | SS_RIGHT,
                          250, 200, 80, 20, hwnd, NULL, NULL, NULL);
            hPasswordEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "password123", 
                                         WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_PASSWORD,
                                         340, 200, 150, 25, hwnd, (HMENU)ID_PASSWORD_EDIT, 
                                         NULL, NULL);

            hLoginButton = CreateWindowEx(0, "BUTTON", "Login", 
                                        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                        340, 250, 80, 30, hwnd, (HMENU)ID_LOGIN_BUTTON, 
                                        NULL, NULL);

            // Create main interface (initially hidden)
            hConnectButton = CreateWindowEx(0, "BUTTON", "Connect", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          10, 10, 80, 30, hwnd, (HMENU)ID_CONNECT_BUTTON, NULL, NULL);

            hDisconnectButton = CreateWindowEx(0, "BUTTON", "Disconnect", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          100, 10, 80, 30, hwnd, (HMENU)ID_DISCONNECT_BUTTON, NULL, NULL);

            hSyncButton = CreateWindowEx(0, "BUTTON", "Sync", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          190, 10, 60, 30, hwnd, (HMENU)ID_SYNC_BUTTON, NULL, NULL);

            hLockButton = CreateWindowEx(0, "BUTTON", "Lock", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          260, 10, 60, 30, hwnd, (HMENU)ID_LOCK_BUTTON, NULL, NULL);

            hUnlockButton = CreateWindowEx(0, "BUTTON", "Unlock", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          330, 10, 60, 30, hwnd, (HMENU)ID_UNLOCK_BUTTON, NULL, NULL);

            hStatsLabel = CreateWindowEx(0, "STATIC", "Disconnected - Please login first", 
                                       WS_CHILD | WS_VISIBLE,
                                       400, 15, 400, 20, hwnd, (HMENU)ID_STATS_LABEL, 
                                       NULL, NULL);

            // Editor
            CreateWindowEx(0, "STATIC", "Document Editor:", 
                          WS_CHILD | WS_VISIBLE,
                          10, 50, 150, 20, hwnd, NULL, NULL, NULL);
            hEditor = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", 
                                   WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | 
                                   ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL | ES_WANTRETURN,
                                   10, 70, 600, 300, hwnd, (HMENU)ID_EDITOR, NULL, NULL);

            // Set font for editor
            HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                   DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Courier New");
            if (hFont) {
                SendMessage(hEditor, WM_SETFONT, (WPARAM)hFont, TRUE);
            }

            // Users list
            CreateWindowEx(0, "STATIC", "Online Users:", 
                          WS_CHILD | WS_VISIBLE,
                          620, 50, 150, 20, hwnd, NULL, NULL, NULL);
            hUsersList = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", "", 
                                      WS_CHILD | WS_VISIBLE | LBS_NOINTEGRALHEIGHT | WS_VSCROLL,
                                      620, 70, 200, 150, hwnd, (HMENU)ID_USERS_LIST, NULL, NULL);

            // Chat
            CreateWindowEx(0, "STATIC", "Chat:", 
                          WS_CHILD | WS_VISIBLE,
                          620, 230, 150, 20, hwnd, NULL, NULL, NULL);
            hChatDisplay = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", 
                                        WS_CHILD | WS_VISIBLE | ES_MULTILINE | 
                                        ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
                                        620, 250, 200, 150, hwnd, (HMENU)ID_CHAT_DISPLAY, 
                                        NULL, NULL);

            hChatEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", 
                                     WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                     620, 410, 150, 25, hwnd, (HMENU)ID_CHAT_EDIT, NULL, NULL);

            CreateWindowEx(0, "BUTTON", "Send", 
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          780, 410, 40, 25, hwnd, (HMENU)ID_CHAT_SEND, NULL, NULL);

            // Initially show auth panel, hide main interface
            ShowAuthPanel(TRUE);
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_LOGIN_BUTTON:
                    LoginUser();
                    break;
                case ID_CONNECT_BUTTON:
                    ConnectToServer();
                    break;
                case ID_DISCONNECT_BUTTON:
                    DisconnectFromServer();
                    break;
                case ID_SYNC_BUTTON:
                    SendSyncRequest();
                    break;
                case ID_LOCK_BUTTON:
                    SendLockRequest();
                    break;
                case ID_UNLOCK_BUTTON:
                    SendUnlockRequest();
                    break;
                case ID_CHAT_SEND:
                    SendChatMessage();
                    break;
                case ID_EDITOR:
                    if (HIWORD(wParam) == EN_UPDATE && is_connected) {
                        // Could track changes here for real-time collaboration
                        // For simplicity, we'll use manual sync with Sync button
                    }
                    break;
            }
            break;

        case WM_CLOSE:
            DisconnectFromServer();
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// Initialize main window
BOOL InitializeWindow(HINSTANCE hInstance) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "CollaborativeEditor";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClass(&wc)) {
        return FALSE;
    }

    hMainWindow = CreateWindowEx(0, "CollaborativeEditor", "Collaborative Editor",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                850, 500, NULL, NULL, hInstance, NULL);

    return hMainWindow != NULL;
}

// Show/hide authentication panel
void ShowAuthPanel(BOOL show) {
    ShowWindow(hAuthFrame, show);
    ShowWindow(hUsernameEdit, show);
    ShowWindow(hPasswordEdit, show);
    ShowWindow(hLoginButton, show);

    // Show/hide main interface
    ShowWindow(hConnectButton, !show);
    ShowWindow(hDisconnectButton, !show);
    ShowWindow(hSyncButton, !show);
    ShowWindow(hLockButton, !show);
    ShowWindow(hUnlockButton, !show);
    ShowWindow(hStatsLabel, !show);
    ShowWindow(hEditor, !show);
    ShowWindow(hUsersList, !show);
    ShowWindow(hChatDisplay, !show);
    ShowWindow(hChatEdit, !show);
    ShowWindow(GetDlgItem(hMainWindow, ID_CHAT_SEND), !show);

    if (!show) {
        // Enable/disable buttons appropriately
        EnableWindow(hConnectButton, !is_connected);
        EnableWindow(hDisconnectButton, is_connected);
        EnableWindow(hSyncButton, is_connected);
        EnableWindow(hLockButton, is_connected);
        EnableWindow(hUnlockButton, is_connected);
        EnableWindow(hChatEdit, is_connected);
        EnableWindow(GetDlgItem(hMainWindow, ID_CHAT_SEND), is_connected);
        EnableWindow(hEditor, is_connected);
    }
}

// Login user
void LoginUser() {
    GetWindowText(hUsernameEdit, username, sizeof(username));
    GetWindowText(hPasswordEdit, password, sizeof(password));

    if (strlen(username) < 3) {
        MessageBox(hMainWindow, "Username must be at least 3 characters", 
                  "Error", MB_ICONERROR);
        return;
    }
    if (strlen(password) < 3) {
        MessageBox(hMainWindow, "Password must be at least 3 characters", 
                  "Error", MB_ICONERROR);
        return;
    }

    is_authenticated = 1;
    
    // Hide auth panel, show main interface
    ShowAuthPanel(FALSE);
    SetWindowText(hStatsLabel, "Please click Connect to join the editor");
    
    char welcome[100];
    sprintf(welcome, "Logged in as: %s", username);
    SetWindowText(hMainWindow, welcome);
}

// Connect to server
void ConnectToServer() {
    if (is_connected || !is_authenticated) return;

    struct sockaddr_in server_addr;
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client_socket == INVALID_SOCKET) {
        MessageBox(hMainWindow, "Socket creation failed", "Error", MB_ICONERROR);
        return;
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to server
    SetWindowText(hStatsLabel, "Connecting to server...");
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        char error_msg[100];
        sprintf(error_msg, "Connection failed (Error: %d) - make sure server is running", WSAGetLastError());
        MessageBox(hMainWindow, error_msg, "Error", MB_ICONERROR);
        closesocket(client_socket);
        client_socket = INVALID_SOCKET;
        SetWindowText(hStatsLabel, "Connection failed");
        return;
    }

    // Start message receiving thread
    hReceiveThread = CreateThread(NULL, 0, ReceiveMessages, NULL, 0, NULL);
    if (hReceiveThread == NULL) {
        MessageBox(hMainWindow, "Thread creation failed", "Error", MB_ICONERROR);
        closesocket(client_socket);
        client_socket = INVALID_SOCKET;
        SetWindowText(hStatsLabel, "Connection failed");
        return;
    }

    is_connected = 1;
    ShowAuthPanel(FALSE); // Ensure main interface is shown
    SetWindowText(hStatsLabel, "Connected - authenticating...");

    // Send authentication
    char buffer[256];
    sprintf(buffer, "USER:%s", username);
    if (send(client_socket, buffer, strlen(buffer), 0) == SOCKET_ERROR) {
        MessageBox(hMainWindow, "Failed to send username", "Error", MB_ICONERROR);
        DisconnectFromServer();
        return;
    }
    
    AddChatMessage("System", "Connecting to server...");
}

// Disconnect from server
void DisconnectFromServer() {
    if (!is_connected) return;

    is_connected = 0;
    
    if (hReceiveThread) {
        TerminateThread(hReceiveThread, 0);
        CloseHandle(hReceiveThread);
        hReceiveThread = NULL;
    }
    
    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
        client_socket = INVALID_SOCKET;
    }

    ShowAuthPanel(FALSE); // Keep main interface visible
    SetWindowText(hStatsLabel, "Disconnected");
    
    // Clear users list
    SendMessage(hUsersList, LB_RESETCONTENT, 0, 0);
    
    // Add disconnect message to chat
    AddChatMessage("System", "Disconnected from server");
    
    // Update UI state
    EnableWindow(hConnectButton, TRUE);
    EnableWindow(hDisconnectButton, FALSE);
    EnableWindow(hSyncButton, FALSE);
    EnableWindow(hLockButton, FALSE);
    EnableWindow(hUnlockButton, FALSE);
    EnableWindow(hChatEdit, FALSE);
    EnableWindow(GetDlgItem(hMainWindow, ID_CHAT_SEND), FALSE);
}

// Send chat message
void SendChatMessage() {
    if (!is_connected) return;

    char message[1000];
    GetWindowText(hChatEdit, message, sizeof(message));
    
    if (strlen(message) > 0) {
        char buffer[1100];
        sprintf(buffer, "CHAT:%s", message);
        if (send(client_socket, buffer, strlen(buffer), 0) == SOCKET_ERROR) {
            MessageBox(hMainWindow, "Failed to send chat message", "Error", MB_ICONERROR);
            DisconnectFromServer();
            return;
        }
        
        // Clear input
        SetWindowText(hChatEdit, "");
    }
}

// Send sync request
void SendSyncRequest() {
    if (!is_connected) return;
    
    send(client_socket, "SYNC:", 5, 0);
    AddChatMessage("System", "Requesting document sync...");
}

// Send lock request
void SendLockRequest() {
    if (!is_connected) return;
    
    send(client_socket, "LOCK:", 5, 0);
    AddChatMessage("System", "Requesting document lock...");
}

// Send unlock request
void SendUnlockRequest() {
    if (!is_connected) return;
    
    send(client_socket, "UNLOCK:", 7, 0);
    AddChatMessage("System", "Releasing document lock...");
}

// Send cursor position
void SendCursorPosition() {
    if (!is_connected) return;
    
    // Get cursor position from editor
    DWORD cursorPos = SendMessage(hEditor, EM_GETSEL, 0, 0);
    int pos = LOWORD(cursorPos);
    
    char buffer[50];
    sprintf(buffer, "CURSOR:%d", pos);
    send(client_socket, buffer, strlen(buffer), 0);
}

// Update users list
void UpdateUsersList(const char* userData) {
    SendMessage(hUsersList, LB_RESETCONTENT, 0, 0);
    
    // Parse user data format: "USERS:user1,pos,color;user2,pos,color;..."
    char data[1024];
    strcpy(data, userData);
    
    char* token = strtok(data, ";");
    while (token != NULL) {
        char username[100], color[20];
        int cursor_pos;
        
        if (sscanf(token, "%[^,],%d,%[^,]", username, &cursor_pos, color) == 3) {
            char display[150];
            sprintf(display, "%s (pos: %d)", username, cursor_pos);
            SendMessage(hUsersList, LB_ADDSTRING, 0, (LPARAM)display);
        }
        
        token = strtok(NULL, ";");
    }
}

// Update document content
void UpdateDocument(const char* documentContent) {
    EnterCriticalSection(&editor_cs);
    
    // Get current selection to restore cursor position
    DWORD cursorPos = SendMessage(hEditor, EM_GETSEL, 0, 0);
    int start = LOWORD(cursorPos);
    int end = HIWORD(cursorPos);
    
    // Update document content
    SetWindowText(hEditor, documentContent);
    
    // Restore cursor position if possible
    int docLength = GetWindowTextLength(hEditor);
    if (start <= docLength && end <= docLength) {
        SendMessage(hEditor, EM_SETSEL, start, end);
    } else {
        // If position is beyond new length, set to end
        SendMessage(hEditor, EM_SETSEL, docLength, docLength);
    }
    
    LeaveCriticalSection(&editor_cs);
}

// Update statistics
void UpdateStats(const char* stats) {
    SetWindowText(hStatsLabel, stats);
}

// Add message to chat display
void AddChatMessage(const char* username, const char* message) {
    char chat_msg[1100];
    sprintf(chat_msg, "%s: %s\r\n", username, message);
    
    // Append to chat display
    int length = GetWindowTextLength(hChatDisplay);
    SendMessage(hChatDisplay, EM_SETSEL, length, length);
    SendMessage(hChatDisplay, EM_REPLACESEL, 0, (LPARAM)chat_msg);
    
    // Scroll to bottom
    SendMessage(hChatDisplay, EM_LINESCROLL, 0, SendMessage(hChatDisplay, EM_GETLINECOUNT, 0, 0));
}

// Message receiving thread
DWORD WINAPI ReceiveMessages(LPVOID lpParam) {
    char buffer[BUFFER_SIZE];
    int bytes_read;
    int auth_step = 0; // 0 = sent username, 1 = sent password, 2 = authenticated

    while (is_connected && (bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Process different message types
        if (strncmp(buffer, "AUTH:", 5) == 0) {
            // Authentication prompt
            if (strstr(buffer, "username") && auth_step == 0) {
                // Should have already sent username
                auth_step = 1;
            } else if (strstr(buffer, "password") && auth_step == 1) {
                // Send password
                char pass_msg[100];
                sprintf(pass_msg, "PASS:%s", password);
                if (send(client_socket, pass_msg, strlen(pass_msg), 0) == SOCKET_ERROR) {
                    break;
                }
                auth_step = 2;
                AddChatMessage("System", "Sent password, waiting for authentication...");
            }
        }
        else if (strncmp(buffer, "AUTH_SUCCESS:", 13) == 0) {
            // Authentication successful
            auth_step = 2;
            SetWindowText(hStatsLabel, buffer + 13);
            AddChatMessage("System", "Authentication successful! Connected to collaborative editor.");
            
            // Request initial sync
            send(client_socket, "SYNC:", 5, 0);
            
            // Update UI state
            PostMessage(hMainWindow, WM_COMMAND, MAKEWPARAM(ID_CONNECT_BUTTON, 0), 0);
        }
        else if (strncmp(buffer, "ERROR:", 6) == 0) {
            // Error message
            char error_msg[256];
            sprintf(error_msg, "Server error: %s", buffer + 6);
            MessageBox(hMainWindow, error_msg, "Server Error", MB_ICONERROR);
            AddChatMessage("System", error_msg);
            
            if (strstr(buffer + 6, "authentication") || strstr(buffer + 6, "password")) {
                // Authentication error - go back to login
                is_connected = 0;
                PostMessage(hMainWindow, WM_COMMAND, MAKEWPARAM(ID_DISCONNECT_BUTTON, 0), 0);
                break;
            }
        }
        else if (strncmp(buffer, "SUCCESS:", 8) == 0) {
            // Success messages
            if (strstr(buffer, "LOCK_ACQUIRED")) {
                AddChatMessage("System", "Document lock acquired successfully");
                EnableWindow(hLockButton, FALSE);
                EnableWindow(hUnlockButton, TRUE);
            }
            else if (strstr(buffer, "LOCK_RELEASED")) {
                AddChatMessage("System", "Document lock released");
                EnableWindow(hLockButton, TRUE);
                EnableWindow(hUnlockButton, FALSE);
            }
            else if (strstr(buffer, "INSERT_SUCCESS") || strstr(buffer, "DELETE_SUCCESS")) {
                // Operation successful - could update UI accordingly
            }
        }
        else if (strncmp(buffer, "DOCUMENT:", 9) == 0) {
            UpdateDocument(buffer + 9);
        }
        else if (strncmp(buffer, "USERLIST:", 9) == 0) {
            // User list in different format - ignore for now
        }
        else if (strncmp(buffer, "USERS:", 6) == 0) {
            UpdateUsersList(buffer + 6);
        }
        else if (strncmp(buffer, "STATS:", 6) == 0) {
            UpdateStats(buffer + 6);
        }
        else if (strncmp(buffer, "CHAT_MSG:", 9) == 0) {
            // Format: CHAT_MSG:user_id:username:timestamp:is_ai:message
            int user_id, is_ai;
            char username[50], message[1000];
            long timestamp;
            
            if (sscanf(buffer, "CHAT_MSG:%d:%49[^:]:%ld:%d:%[^\n]", 
                       &user_id, username, &timestamp, &is_ai, message) == 5) {
                AddChatMessage(username, message);
            }
        }
        else {
            // Unknown message type - add to chat as system message
            AddChatMessage("System", buffer);
        }
    }
    
    // If we get here, connection was lost
    if (is_connected) {
        is_connected = 0;
        PostMessage(hMainWindow, WM_COMMAND, MAKEWPARAM(ID_DISCONNECT_BUTTON, 0), 0);
    }
    
    return 0;
}