const socket = io();

const message = document.getElementById('message');
const handle = document.getElementById('handle');
const btn = document.getElementById('send');
const logoutBtn = document.getElementById('logout');
const attachBtn = document.getElementById('attach-btn');
const fileInput = document.getElementById('file-input');
const output = document.getElementById('output');
const feedback = document.getElementById('feedback');
const chatApp = document.getElementById('chat-app');
const onlineUsersList = document.getElementById('online-users-list');
const themeToggle = document.getElementById('theme-toggle'); // New element
const currentChatName = document.getElementById('current-chat-name');
const changeNameBtn = document.getElementById('change-name-btn');
const clearHistoryBtn = document.getElementById('clear-history-btn');

const authScreen = document.getElementById('auth-screen');
let currentChatTarget = 'General'; 
let messagesStore = { 'General': [] };
let usersList = [];

let mediaRecorder;
let audioChunks = [];
let myKeyPair; 


let peerConnection;
let localStream;
const iceServers = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

const startCallBtn = document.getElementById('start-call-btn');
const callOverlay = document.getElementById('call-overlay');
const callStatus = document.getElementById('call-status');
const hangupBtn = document.getElementById('hangup-btn');
const acceptCallBtn = document.getElementById('accept-call-btn');


let encryptionCache = new Map(JSON.parse(localStorage.getItem('encryption_cache') || '[]'));


function applyTheme(theme) {
    document.body.classList.toggle('dark-mode', theme === 'dark');
    localStorage.setItem('theme', theme);
}

themeToggle.addEventListener('click', () => {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(newTheme);
});


const savedTheme = localStorage.getItem('theme') || 'light';
applyTheme(savedTheme);



async function getOrGenerateKeys(userHandle) {
    const storageKey = `chat_keys_${userHandle}`;
    const saved = localStorage.getItem(storageKey);
    if (saved) {
        const { publicJwk, privateJwk } = JSON.parse(saved);
        const publicKey = await window.crypto.subtle.importKey("jwk", publicJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
        const privateKey = await window.crypto.subtle.importKey("jwk", privateJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
        return { keys: { publicKey, privateKey }, publicKeyJwk: publicJwk };
    }
    const keys = await window.crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true, ["encrypt", "decrypt"]
    );
    const publicJwk = await window.crypto.subtle.exportKey("jwk", keys.publicKey);
    const privateJwk = await window.crypto.subtle.exportKey("jwk", keys.privateKey);
    localStorage.setItem(storageKey, JSON.stringify({ publicJwk, privateJwk }));
    return { keys, publicKeyJwk: publicJwk };
}

async function encryptData(text, publicKeyJwk) {
    const key = await window.crypto.subtle.importKey(
        "jwk", publicKeyJwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true, ["encrypt"]
    );
    const encoded = new TextEncoder().encode(text);
    const encrypted = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, encoded);
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptData(encryptedBase64, privateKey) {
    try {
        const encryptedBuffer = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const decrypted = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedBuffer);
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        return "[Decryption error: keys might have changed]";
    }
}


function askForCode() {
    const code = prompt("Please enter the secret code:");
    if (code !== null) {
        console.log("Client: Emitting 'verify-code' with code:", code);
        socket.emit('verify-code', code);
    }
}

socket.on('auth-result', async (data) => {
    console.log("Client: Received 'auth-result':", data);
    if (data.success) {
        chatApp.style.display = 'flex';
        let savedName = localStorage.getItem('chat_user_name');
        if (!savedName) {
            savedName = prompt("What is your name?") || "User";
        }

        handle.value = savedName;
        console.log("Client: Emitting 'set-handle' with name:", savedName);
        socket.emit('set-handle', savedName); // Send handle to server for validation
        authScreen.style.display = 'none'; // Hide auth screen after handle is sent

        let roomName =
            prompt("Room Name:", "General");

        if (!roomName || roomName.trim() === "") {
            roomName = "General";
        }

        socket.emit('join-room', roomName);

        currentChatTarget = roomName;
       
        if (!messagesStore[roomName]) messagesStore[roomName] = [];
        
        currentChatName.innerText = "Room: " + roomName;

       
        document.getElementById('call-actions').style.display = roomName === 'General' ? 'none' : 'block';

        handle.disabled = true;

    } else {
        authScreen.style.display = 'flex'; 
        alert(data.message || "Incorrect code");
        askForCode();
    }
});


askForCode();



logoutBtn.addEventListener('click', () => {
    localStorage.clear();
    location.reload();
});

clearHistoryBtn.addEventListener('click', () => {
    if (confirm("Are you sure you want to delete ALL chat history from the server? This cannot be undone.")) {
        socket.emit('clear-history');
    }
});

changeNameBtn.addEventListener('click', () => {
    const newName = prompt("Enter your new name:", handle.value);
    if (newName && newName.trim() !== "" && newName !== handle.value) {
        socket.emit('set-handle', newName.trim());
    }
});

socket.on('handle-error', (msg) => {
    alert(msg);
    const name = prompt("Please choose another name:");
    if (name) socket.emit('set-handle', name.trim());
});

socket.on('handle-confirmed', async (confirmedName) => {
    console.log("Client: Received 'handle-confirmed':", confirmedName);
    const oldName = handle.value;
    localStorage.setItem('chat_user_name', confirmedName);
    handle.value = confirmedName;

    // Generate and register encryption keys for the confirmed name
    const { keys, publicKeyJwk } = await getOrGenerateKeys(confirmedName);
    myKeyPair = keys;
    console.log("Client: Emitting 'register-public-key' for handle:", confirmedName);
    socket.emit('register-public-key', { handle: confirmedName, publicKey: publicKeyJwk });

    if (oldName && oldName !== confirmedName && oldName !== "User") {
        alert(`Name successfully updated to ${confirmedName}`);
    }
});


async function uploadFileToServer(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/upload', {
        method: 'POST',
        body: formData
    });

    return await response.json();
}


async function sendMessage() {
    const msgText = message.value.trim();
    const senderHandle = handle.value;

    if (msgText === "" || !senderHandle) {
        console.warn("Client: sendMessage aborted - empty message or handle.");
        return;
    }

    console.log("Client: sendMessage called. Target:", currentChatTarget, "Message:", msgText);

    if (currentChatTarget !== 'General') {
       
        socket.emit('get-public-key', currentChatTarget, async (recipientKey) => {
            console.log("Client: Received public key for", currentChatTarget, ":", recipientKey ? "found" : "not found");
            if (recipientKey) {
                const encryptedMsg = await encryptData(msgText, recipientKey);
                
               
                encryptionCache.set(encryptedMsg, msgText);
                
                if (encryptionCache.size > 200) encryptionCache.delete(encryptionCache.keys().next().value);
                localStorage.setItem('encryption_cache', JSON.stringify([...encryptionCache]));

                console.log("Client: Emitting 'send-private-message' (encrypted).");
                socket.emit('send-private-message', {
                    recipientHandle: currentChatTarget,
                    message: encryptedMsg,
                    senderHandle: senderHandle,
                    timestamp: new Date().toISOString()
                });
            } else {
                alert("Could not retrieve encryption key for this user.");
            }
        });
    } else {
        // Public message
        console.log("Client: Emitting 'chat' (public).");
        socket.emit('chat', {
            type: 'text',
            message: msgText,
            handle: senderHandle,
            timestamp: new Date().toISOString() // Add timestamp
        });
    }
    message.value = "";
}



btn.addEventListener('click', sendMessage);



message.addEventListener('keydown', (e) => {

    socket.emit('typing', handle.value);

    if (e.key === 'Enter') {
        sendMessage();
    }

});



attachBtn.addEventListener('click', () => {

    fileInput.click();

});



fileInput.addEventListener('change', async (e) => {

    const file = e.target.files[0];
    if (!file) return;

    if (file.size > 50 * 1024 * 1024) { 
        alert("File is too large");
        return;
    }
    const type = 'file';

    try {
        const data = await uploadFileToServer(file);
        socket.emit('chat', {
            type: type,
            message: data.filePath,
            handle: handle.value,
            fileName: data.originalName,
            timestamp: new Date().toISOString() 
        });
    } catch (err) {
        alert("File upload failed");
    }
});


function getMessageTargetKey(data) {
    if (data.recipientHandle) {
        
        return (data.senderHandle === handle.value) ? data.recipientHandle : data.senderHandle;
    }
    return 'General';
}

function addMessageToUI(data, shouldStore = true) {
    const targetKey = getMessageTargetKey(data);
    
   
    if (shouldStore) {
        if (!messagesStore[targetKey]) messagesStore[targetKey] = [];
        messagesStore[targetKey].push(data);
    }

    
    if (targetKey !== currentChatTarget) return;

    feedback.innerHTML = "";

    const messageElement =
        document.createElement('div');

    
    const senderIsMe = data.handle === handle.value || (data.handle && data.handle.includes("private to")) || data.senderHandle === handle.value;
    
    messageElement.classList.add('chat-message');
    messageElement.classList.add(senderIsMe ? 'sent' : 'received');
    messageElement.setAttribute('data-id', data.id); 
    
   
    if (!senderIsMe) {
        const headerWrapper = document.createElement('div');
        headerWrapper.classList.add('chat-header');
        const strong = document.createElement('strong');
        strong.textContent = data.handle;
        headerWrapper.appendChild(strong);
        messageElement.appendChild(headerWrapper);
    }

    
    const contentWrapper = document.createElement('div');
    contentWrapper.classList.add('chat-content-wrapper');

    let contentElement; 
    if (data.type === 'deleted') {
        contentElement = document.createElement('p');
        const em = document.createElement('em');
        em.textContent = '🚫 This message was deleted';
        contentElement.appendChild(em);
        contentElement.style.color = '#999';
    } else if (data.type === 'text') {
        contentElement =
            document.createElement('p');
        contentElement.innerText =
            data.message;
    } else if (data.type === 'image') {
        contentElement =
            document.createElement('img');
        contentElement.src =
            data.message;
        contentElement.loading = "lazy";
        contentElement.alt = "Sent image";
    } else if (data.type === 'video') {
        contentElement =
            document.createElement('video');
        contentElement.src =
            data.message;
        contentElement.controls = true;
    } else if (data.type === 'audio') {
        contentElement =
            document.createElement('audio');
        contentElement.src =
            data.message;
        contentElement.controls = true;
    } else if (data.type === 'file') {
        contentElement =
            document.createElement('a');
        contentElement.href =
            data.message;
        contentElement.innerText = "📄 " + (data.fileName || "attached file");
        contentElement.target = "_blank";
        contentElement.style.display = "block";
    }

    
    if (contentElement) {
        contentWrapper.appendChild(contentElement);
    }

   
    if (senderIsMe && data.type !== 'deleted' && data.id) {
        const deleteBtn = document.createElement('span');
        deleteBtn.innerHTML = ' 🗑️';
        deleteBtn.style.cursor = 'pointer';
        deleteBtn.style.fontSize = '0.8em';
        deleteBtn.title = 'Delete for everyone';
        deleteBtn.onclick = () => {
            if (confirm('Do you want to delete this message for everyone?')) {
                socket.emit('delete-message', { id: data.id });
            }
        };
        contentWrapper.appendChild(deleteBtn);
    }

    messageElement.appendChild(contentWrapper);

   
    const metaWrapper = document.createElement('div');
    metaWrapper.style.textAlign = 'right';
    metaWrapper.style.marginTop = '4px';
    
    if (data.timestamp) {
        const timestampElement = document.createElement('span');
        timestampElement.classList.add('message-timestamp');
        const date = new Date(data.timestamp);
        timestampElement.innerText = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        metaWrapper.appendChild(timestampElement);
    }

    if (senderIsMe) metaWrapper.innerHTML += '<span class="ticks">✓✓</span>';
    messageElement.appendChild(metaWrapper);

    output.appendChild(messageElement);
    
    const chatWindow = document.getElementById('chat-window');
    if (chatWindow) {
        chatWindow.scrollTo({ top: chatWindow.scrollHeight, behavior: 'smooth' });
    }
}


socket.on('online-users', (users) => {
    onlineUsersList.innerHTML = ''; 

    
    const generalLi = document.createElement('li');
    generalLi.innerHTML = "<strong>📢 General Chat</strong>";
    if (currentChatTarget === 'General') generalLi.classList.add('active-chat');
    generalLi.onclick = () => switchChat('General');
    onlineUsersList.appendChild(generalLi);

    users.forEach(userHandle => {
        if (userHandle === handle.value) return; 
        const li = document.createElement('li');
        li.innerText = userHandle;
        if (userHandle === currentChatTarget) li.classList.add('active-chat');
        li.addEventListener('click', () => {
            switchChat(userHandle);
        });
        onlineUsersList.appendChild(li);
    });
});

function switchChat(target) {
    currentChatTarget = target;
    currentChatName.innerText = target === 'General' ? "Room: General" : "Private chat with: " + target;
    document.getElementById('call-actions').style.display = target === 'General' ? 'none' : 'block';
    
    output.innerHTML = ""; 
    (messagesStore[target] || []).forEach(msg => addMessageToUI(msg, false));
    message.focus();
   
    socket.emit('get-online-users'); 
}


socket.on('force-reset-local', () => {
    console.log("⚠️ Administrator cleared all user data.");
    localStorage.clear();
    location.reload();
});


socket.on('message-deleted', (data) => {
    
    Object.keys(messagesStore).forEach(room => {
        messagesStore[room] = messagesStore[room].map(msg => {
            if (msg.id === data.id) {
                return { ...msg, type: 'deleted', message: '🚫 This message was deleted' };
            }
            return msg;
        });
    });

    
    const msgDiv = document.querySelector(`.chat-message[data-id="${data.id}"]`);
    if (msgDiv) {
        const contentWrapper = msgDiv.querySelector('.chat-content-wrapper');
        if (contentWrapper) {
            contentWrapper.innerHTML = ''; // Clear previous content
            const p = document.createElement('p');
            p.style.color = '#999';
            const em = document.createElement('em');
            em.textContent = '🚫 This message was deleted';
            p.appendChild(em);
            contentWrapper.appendChild(p);
        }
    }
});


socket.on('history-cleared', () => {
    messagesStore = { 'General': [] };
    output.innerHTML = "";
    alert("Chat history has been cleared by an administrator.");
});


socket.on('chat', async (data) => {
    if (data.isEncrypted) {
       
        if (data.handle && data.handle.includes("private from") && myKeyPair) {
            data.message = await decryptData(data.message, myKeyPair.privateKey);
        } else if (data.handle && data.handle.includes("private to") && encryptionCache.has(data.message)) {
           
            data.message = encryptionCache.get(data.message);
        }
    }
    console.log("Client: Received 'chat' event:", data);
    addMessageToUI(data);
});


socket.on('chat-history', async (history) => {
    output.innerHTML = ""; 
    messagesStore = { 'General': [] }; 
    for (const data of history) {
        if (data.isEncrypted && data.handle && data.handle.includes("private from") && myKeyPair) {
            data.message = await decryptData(data.message, myKeyPair.privateKey);
        } else if (data.isEncrypted && data.handle && data.handle.includes("private to") && encryptionCache.has(data.message)) {
            
            data.message = encryptionCache.get(data.message);
        }
        addMessageToUI(data); 
    }
});



socket.on('typing', (data) => {

    feedback.innerHTML = '';
    const em = document.createElement('em');
    em.textContent = `${data} is typing...`;
    feedback.appendChild(em);

});



async function initPeerConnection(targetUser) {
    peerConnection = new RTCPeerConnection(iceServers);
    
    peerConnection.onicecandidate = ({ candidate }) => {
        if (candidate) socket.emit('ice-candidate', { to: targetUser, candidate });
    };

    peerConnection.ontrack = ({ streams }) => {
        const remoteAudio = new Audio();
        remoteAudio.srcObject = streams[0];
        remoteAudio.play();
    };

    localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
}

startCallBtn.onclick = async () => {
    await initPeerConnection(currentChatTarget);
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    
    socket.emit('call-user', { to: currentChatTarget, offer });
    callStatus.innerText = `Calling ${currentChatTarget}...`;
    callOverlay.style.display = 'block';
    acceptCallBtn.style.display = 'none';
};

socket.on('incoming-call', async (data) => {
    switchChat(data.from); 
    callStatus.innerText = `Incoming call from ${data.from}`;
    callOverlay.style.display = 'block';
    acceptCallBtn.style.display = 'inline-block';
    
    acceptCallBtn.onclick = async () => {
        await initPeerConnection(data.from);
        await peerConnection.setRemoteDescription(new RTCSessionDescription(data.offer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        
        socket.emit('make-answer', { to: data.from, answer });
        callStatus.innerText = "In call...";
        acceptCallBtn.style.display = 'none';
    };
});

socket.on('answer-made', async (data) => {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
    callStatus.innerText = "In call...";
});

socket.on('ice-candidate', async (data) => {
    try {
        if (peerConnection) await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
    } catch (e) { console.error(e); }
});

hangupBtn.onclick = () => {
    endCall();
    socket.emit('hang-up', { to: currentChatTarget });
};

socket.on('call-ended', () => {
    endCall();
    alert("Call ended");
});

function endCall() {
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
    }
    callOverlay.style.display = 'none';
}
