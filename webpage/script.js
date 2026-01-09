        document.addEventListener('DOMContentLoaded', function() {
            // Toolbar elements
            const fileBtn = document.getElementById('fileBtn');
            const fileDropdown = document.getElementById('fileDropdown');
            const insertBtn = document.getElementById('insertBtn');
            const insertDropdown = document.getElementById('insertDropdown');
            const aiCompletionsBtn = document.getElementById('aiCompletionsBtn');
            const historyBtn = document.getElementById('historyBtn');

            // Sidebar panels
            const teamChatPanel = document.getElementById('teamChatPanel');
            const usersPanel = document.getElementById('usersPanel');
            const aiChatPanel = document.getElementById('aiChatPanel');

            // Insert Media Panel
            const insertMediaPanel = document.getElementById('insertMediaPanel');
            const photoOption = document.getElementById('photoOption');
            const videoOption = document.getElementById('videoOption');

            // AI Chat elements
            const aiChatInput = document.getElementById('aiChatInput');
            const aiSendBtn = document.getElementById('aiSendBtn');
            const aiChatMessages = document.getElementById('aiChatMessages');

            // Editor elements
            const zoomInBtn = document.getElementById('zoomIn');
            const zoomOutBtn = document.getElementById('zoomOut');
            const zoomValue = document.getElementById('zoomValue');
            const sendBtn = document.querySelector('.send-btn');
            const chatInput = document.querySelector('.chat-input input');
            const editorContent = document.getElementById('editorContent');
            const lineNumbers = document.getElementById('lineNumbers');
            const dropdownItems = document.querySelectorAll('.dropdown-item');

            let zoomLevel = 100;
            let isAIChatOpen = false;

            // Toggle dropdown menus
            fileBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                fileDropdown.classList.toggle('show');
                insertDropdown.classList.remove('show');
            });

            insertBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                insertDropdown.classList.toggle('show');
                fileDropdown.classList.remove('show');
            });

            // Close dropdowns when clicking outside
            document.addEventListener('click', function() {
                fileDropdown.classList.remove('show');
                insertDropdown.classList.remove('show');
            });

            // Handle dropdown item clicks
            dropdownItems.forEach(item => {
                item.addEventListener('click', function(e) {
                    const action = this.querySelector('span').textContent;

                    if (action === 'Photo' || action === 'Video') {
                        // Show the insert media panel
                        insertMediaPanel.classList.add('show-insert-media');
                        insertDropdown.classList.remove('show');
                    } else {
                        showNotification(`Action: ${action}`);
                        fileDropdown.classList.remove('show');
                        insertDropdown.classList.remove('show');
                    }
                });
            });

            // Handle media option clicks
            photoOption.addEventListener('click', function() {
                showNotification('Opening photo insertion dialog...');
                insertMediaPanel.classList.remove('show-insert-media');
            });

            videoOption.addEventListener('click', function() {
                showNotification('Opening video insertion dialog...');
                insertMediaPanel.classList.remove('show-insert-media');
            });

            // Close insert media panel when clicking outside
            document.addEventListener('click', function(event) {
                if (!insertMediaPanel.contains(event.target) &&
                    !insertBtn.contains(event.target) &&
                    !insertDropdown.contains(event.target)) {
                    insertMediaPanel.classList.remove('show-insert-media');
                }
            });

            // AI Chat Toggle
            aiCompletionsBtn.addEventListener('click', function() {
                isAIChatOpen = !isAIChatOpen;

                if (isAIChatOpen) {
                    // Show AI chat, hide team chat and users panel
                    aiChatPanel.style.display = 'flex';
                    teamChatPanel.style.display = 'none';
                    usersPanel.style.display = 'none';
                    aiCompletionsBtn.classList.add('active');
                } else {
                    // Hide AI chat, show team chat and users panel
                    aiChatPanel.style.display = 'none';
                    teamChatPanel.style.display = 'flex';
                    usersPanel.style.display = 'block';
                    aiCompletionsBtn.classList.remove('active');
                }
            });

            // AI Chat functionality
            aiSendBtn.addEventListener('click', sendAIMessage);
            aiChatInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendAIMessage();
                }
            });

            function sendAIMessage() {
                const message = aiChatInput.value.trim();
                if (!message) return;

                const user = users[currentUser];

                // Add user message
                const userMessageDiv = document.createElement('div');
                userMessageDiv.className = 'ai-message user-query';
                userMessageDiv.innerHTML = `
                    <div class="ai-avatar" style="background-color: ${user.color}">${user.avatar}</div>
                    <div class="ai-message-content">
                        <div class="ai-message-text">${message}</div>
                    </div>
                `;
                aiChatMessages.appendChild(userMessageDiv);
                aiChatInput.value = '';
                aiChatMessages.scrollTop = aiChatMessages.scrollHeight;

                // Simulate AI response
                setTimeout(() => {
                    let aiResponse = '';
                    if (message.toLowerCase().includes('hello') || message.toLowerCase().includes('hi')) {
                        aiResponse = 'Hello there! How can I assist you with your document today?';
                    } else if (message.toLowerCase().includes('help')) {
                        aiResponse = 'Of course! I can help you with grammar, spelling, and even suggest content. What do you need help with?';
                    } else if (message.toLowerCase().includes('paragraph')) {
                        aiResponse = 'I can certainly help with that. Please select the paragraph you want me to review, and I will provide suggestions.';
                    } else {
                        aiResponse = `I'm not sure how to respond to "${message}". I am a simulated AI assistant with a limited set of responses. Try asking me for 'help' or to review a 'paragraph'.`;
                    }

                    const aiResponseDiv = document.createElement('div');
                    aiResponseDiv.className = 'ai-message ai-response';
                    aiResponseDiv.innerHTML = `
                        <div class="ai-avatar">AI</div>
                        <div class="ai-message-content">
                            <div class="ai-message-text">${aiResponse}</div>
                        </div>
                    `;
                    aiChatMessages.appendChild(aiResponseDiv);
                    aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
                }, 1000);
            }

            // Update line numbers
            function updateLineNumbers() {
                const text = editorContent.innerText.replace(/\n$/, ''); // Ignore trailing newline
                const lines = text.split('\n').length;
                let lineNumbersHTML = '';

                for (let i = 1; i <= lines; i++) {
                    lineNumbersHTML += `<div>${i}</div>`;
                }

                lineNumbers.innerHTML = lineNumbersHTML;

                // Sync scrolling
                lineNumbers.scrollTop = editorContent.scrollTop;
            }

            // Initialize line numbers
            updateLineNumbers();

            // Update line numbers when content changes
            editorContent.addEventListener('input', function() {
                updateLineNumbers();
                updateWordCount();
            });

            // Update line numbers on resize
            window.addEventListener('resize', updateLineNumbers);

            // Sync scrolling
            editorContent.addEventListener('scroll', function() {
                lineNumbers.scrollTop = editorContent.scrollTop;
            });

            // Add user cursors (simulated for demo)
            function addUserCursors() {
                // Remove existing cursors
                document.querySelectorAll('.user-cursor').forEach(el => el.remove());

                // Add cursor for current user (user1)
                const user1Cursor = document.createElement('div');
                user1Cursor.className = 'user-cursor';
                user1Cursor.style.backgroundColor = '#667eea';
                user1Cursor.style.left = '50px';
                user1Cursor.style.top = '100px';
                editorContent.appendChild(user1Cursor);

                // Add cursor for user2
                const user2Cursor = document.createElement('div');
                user2Cursor.className = 'user-cursor';
                user2Cursor.style.backgroundColor = '#ed8936';
                user2Cursor.style.width = '3px'; // Broader cursor
                user2Cursor.style.left = '200px';
                user2Cursor.style.top = '150px';
                editorContent.appendChild(user2Cursor);

                // Add cursor for user3
                const user3Cursor = document.createElement('div');
                user3Cursor.className = 'user-cursor';
                user3Cursor.style.backgroundColor = '#9f7aea';
                user3Cursor.style.width = '3px'; // Broader cursor
                user3Cursor.style.left = '300px';
                user3Cursor.style.top = '200px';
                editorContent.appendChild(user3Cursor);
            }

            // Initialize user cursors
            setTimeout(addUserCursors, 1000);

            // History Panel Toggle
            historyBtn.addEventListener('click', function() {
                showNotification('Opening Version History panel...');
            });

            // Zoom Controls
            zoomInBtn.addEventListener('click', function() {
                if (zoomLevel < 200) {
                    zoomLevel += 10;
                    zoomValue.textContent = zoomLevel + '%';
                    editorContent.style.fontSize = (zoomLevel / 100) + 'em';
                    updateLineNumbers();
                }
            });

            zoomOutBtn.addEventListener('click', function() {
                if (zoomLevel > 50) {
                    zoomLevel -= 10;
                    zoomValue.textContent = zoomLevel + '%';
                    editorContent.style.fontSize = (zoomLevel / 100) + 'em';
                    updateLineNumbers();
                }
            });

            // Chat functionality
            sendBtn.addEventListener('click', sendMessage);
            chatInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });

            function sendMessage() {
                const message = chatInput.value.trim();
                if (!message) return;

                const user = users[currentUser];
                const chatMessages = document.querySelector('.chat-messages');
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${currentUser}`;
                messageDiv.innerHTML = `
                    <div class="message-avatar" style="background-color: ${user.color}">${user.avatar}</div>
                    <div class="message-content">
                        <div class="message-info">
                            <span class="message-sender">${user.name}</span>
                            <span class="message-time">Just now</span>
                        </div>
                        <div class="message-text">${message}</div>
                    </div>
                `;
                chatMessages.appendChild(messageDiv);
                chatInput.value = '';
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }

            // Update word count
function showNotification(message) {
    const container = document.getElementById('notification-container');
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    container.appendChild(notification);

    setTimeout(() => {
        notification.classList.add('show');
    }, 100);

    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            container.removeChild(notification);
        }, 300);
    }, 3000);
}

            function updateWordCount() {
                const text = editorContent.innerText || '';
                const wordCount = text.trim() === '' ? 0 : text.trim().split(/\s+/).length;
                document.querySelector('.status-item:nth-child(2) span').textContent = Words: ${wordCount};
            }

            // Initialize
            updateWordCount();

            // Dynamic User System
            const users = {
                user1: { name: 'user1', avatar: 'U1', color: '#667eea' },
                user2: { name: 'user2', avatar: 'U2', color: '#ed8936' },
                user3: { name: 'user3', avatar: 'U3', color: '#9f7aea' },
                user4: { name: 'user4', avatar: 'U4', color: '#38a169' }
            };

            let currentUser = 'user1';

            const userSelector = document.getElementById('userSelector');
            const currentUserName = document.getElementById('currentUserName');
            const currentUserAvatar = document.getElementById('currentUserAvatar');

            userSelector.addEventListener('change', (e) => {
                currentUser = e.target.value;
                updateUserInfo();
            });

            function updateUserInfo() {
                const user = users[currentUser];
                currentUserName.textContent = user.name;
                currentUserAvatar.textContent = user.avatar;
                currentUserAvatar.style.backgroundColor = user.color;
            }

            // Text Formatting
            const boldBtn = document.getElementById('boldBtn');
            const italicBtn = document.getElementById('italicBtn');
            const underlineBtn = document.getElementById('underlineBtn');

            boldBtn.addEventListener('click', () => {
                document.execCommand('bold');
            });

            italicBtn.addEventListener('click', () => {
                document.execCommand('italic');
            });

            underlineBtn.addEventListener('click', () => {
                document.execCommand('underline');
            });
        });
