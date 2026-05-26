const socket = io();

const message = document.getElementById('message');
const handle = document.getElementById('handle');
const btn = document.getElementById('send');
const logoutBtn = document.getElementById('logout');
const attachBtn = document.getElementById('attach-btn');
const recordBtn = document.getElementById('record-btn');
const fileInput = document.getElementById('file-input');
const output = document.getElementById('output');
const feedback = document.getElementById('feedback');
const chatApp = document.getElementById('chat-app');
const onlineUsersList = document.getElementById('online-users-list');
const themeToggle = document.getElementById('theme-toggle'); // New element
const currentChatName = document.getElementById('current-chat-name');

const authScreen = document.getElementById('auth-screen');
let currentChatTarget = 'General'; // 'General' means the group, otherwise it's a username
let messagesStore = { 'General': [] };
let usersList = [];

let mediaRecorder;
let audioChunks = [];
let myKeyPair; // لتخزين مفاتيح التشفير الخاصة بالمستخدم

// WebRTC Variables
let peerConnection;
let localStream;
const iceServers = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

const startCallBtn = document.getElementById('start-call-btn');
const callOverlay = document.getElementById('call-overlay');
const callStatus = document.getElementById('call-status');
const hangupBtn = document.getElementById('hangup-btn');
const acceptCallBtn = document.getElementById('accept-call-btn');

// ذاكرة محلية لتخزين النصوص الأصلية للرسائل التي ترسلها (لأنها مشفرة للمستقبل فقط)
let encryptionCache = new Map(JSON.parse(localStorage.getItem('encryption_cache') || '[]'));

// --- Theme Toggle Logic ---
function applyTheme(theme) {
    document.body.classList.toggle('dark-mode', theme === 'dark');
    localStorage.setItem('theme', theme);
}

themeToggle.addEventListener('click', () => {
    const currentTheme = localStorage.getItem('theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(newTheme);
});

// Apply saved theme on load
const savedTheme = localStorage.getItem('theme') || 'light';
applyTheme(savedTheme);
// --- End Theme Toggle Logic ---

// --- Encryption Utilities ---
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
        return "[خطأ في فك التشفير: ربما تغيرت المفاتيح]";
    }
}
// --- End Encryption Utilities ---

function askForCode() {
    const code = prompt("الرجاء إدخال الكود السري:");
    if (code !== null) {
        socket.emit('verify-code', code);
    }
}

socket.on('auth-result', async (data) => {
    if (data.success) {
        authScreen.style.display = 'none'; // إخفاء شاشة التحقق
        chatApp.style.display = 'flex';
        let savedName =
            localStorage.getItem('chat_user_name');

        if (!savedName) {

            savedName =
                prompt("ما هو اسمك؟");

            if (savedName) {
                localStorage.setItem(
                    'chat_user_name',
                    savedName
                );
            }
        }

        handle.value = savedName || "مستخدم";
        socket.emit('set-handle', handle.value); // إرسال الاسم للسيرفر بعد التحقق

        // توليد وتسجيل مفاتيح التشفير
        const { keys, publicKeyJwk } = await getOrGenerateKeys(handle.value);
        myKeyPair = keys;
        socket.emit('register-public-key', { handle: handle.value, publicKey: publicKeyJwk });

        let roomName =
            prompt("اسم الغرفة:", "General");

        if (!roomName || roomName.trim() === "") {
            roomName = "General";
        }

        socket.emit('join-room', roomName);

        currentChatTarget = roomName;
        // تهيئة مخزن الرسائل للغرفة الافتراضية
        if (!messagesStore[roomName]) messagesStore[roomName] = [];
        
        currentChatName.innerText = "غرفة: " + roomName;

        // إخفاء أزرار الاتصال في الغرف العامة
        document.getElementById('call-actions').style.display = roomName === 'General' ? 'none' : 'block';

        handle.disabled = true;

    } else {
        authScreen.style.display = 'flex'; // إظهار شاشة التحقق مرة أخرى
        alert(data.message || "الكود خاطئ");
        askForCode();
    }
});

// بدء عملية التحقق مباشرة عند تحميل الصفحة
askForCode();



logoutBtn.addEventListener('click', () => {

    localStorage.removeItem('chat_user_name');

    location.reload();

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
        return;
    }

    if (currentChatTarget !== 'General') {
        // طلب مفتاح المستقبل وتشفير الرسالة
        socket.emit('get-public-key', currentChatTarget, async (recipientKey) => {
            if (recipientKey) {
                const encryptedMsg = await encryptData(msgText, recipientKey);
                
                // حفظ النص الأصلي محلياً مرتبطاً بالنص المشفر لنتمكن من رؤيته لاحقاً
                encryptionCache.set(encryptedMsg, msgText);
                // الحفاظ على حجم الذاكرة (آخر 200 رسالة مثلاً)
                if (encryptionCache.size > 200) encryptionCache.delete(encryptionCache.keys().next().value);
                localStorage.setItem('encryption_cache', JSON.stringify([...encryptionCache]));

                socket.emit('send-private-message', {
                    recipientHandle: currentChatTarget,
                    message: encryptedMsg,
                    senderHandle: senderHandle,
                    timestamp: new Date().toISOString()
                });
            } else {
                alert("تعذر الحصول على مفتاح التشفير لهذا المستخدم.");
            }
        });
    } else {
        // رسالة عامة
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

    if (file.size > 50 * 1024 * 1024) { // حد أقصى 50 ميجا مثلاً
        alert("الملف كبير جداً");
        return;
    }

    let type = '';
    if (file.type.startsWith('image/')) {
        type = 'image';
    } else if (file.type.startsWith('video/')) {
        type = 'video';
    } else {
        type = 'file';
    }

    try {
        const data = await uploadFileToServer(file);
        socket.emit('chat', {
            type: type,
            message: data.filePath,
            handle: handle.value,
            fileName: data.originalName,
            timestamp: new Date().toISOString() // Add timestamp
        });
    } catch (err) {
        alert("فشل رفع الملف");
    }
});



recordBtn.addEventListener('click', async () => {

    if (
        !window.isSecureContext &&
        window.location.hostname !== "localhost"
    ) {

        alert(
            "الميكروفون يحتاج HTTPS"
        );

        return;
    }



    if (
        !mediaRecorder ||
        mediaRecorder.state === 'inactive'
    ) {

        try {

            const stream =
                await navigator.mediaDevices.getUserMedia({
                    audio: true
                });

            mediaRecorder =
                new MediaRecorder(stream);

            audioChunks = [];



            mediaRecorder.ondataavailable = e => {

                audioChunks.push(e.data);

            };



            mediaRecorder.onstop = async () => {
                const blob =
                    new Blob(audioChunks, {
                        type: 'audio/webm'
                    });
                
                const file = new File([blob], "voice_msg.webm", { type: 'audio/webm' });
                const data = await uploadFileToServer(file);
                socket.emit('chat', {
                    type: 'audio',
                    message: data.filePath,
                    handle: handle.value,
                    timestamp: new Date().toISOString() // Add timestamp
                });
            };



            mediaRecorder.start();

            recordBtn.classList.add('recording');

            recordBtn.innerText = '🛑';

        } catch (err) {

            alert(
                "تعذر تشغيل الميكروفون"
            );
        }

    } else {

        mediaRecorder.stop();

        recordBtn.classList.remove('recording');

        recordBtn.innerText = '🎤';

    }
});

// دالة لتحديد "المفتاح" الذي سنخزن تحته الرسالة (اسم المستخدم أو General)
function getMessageTargetKey(data) {
    if (data.recipientHandle) {
        // إذا كنت أنا المرسل، فالمفتاح هو المستلم. إذا كنت المستلم، فالمفتاح هو المرسل.
        return (data.senderHandle === handle.value) ? data.recipientHandle : data.senderHandle;
    }
    return 'General';
}

// دالة لإضافة الرسالة إلى الواجهة
function addMessageToUI(data, shouldStore = true) {
    const targetKey = getMessageTargetKey(data);
    
    // تخزين الرسالة في الذاكرة المحلية (messagesStore)
    if (shouldStore) {
        if (!messagesStore[targetKey]) messagesStore[targetKey] = [];
        messagesStore[targetKey].push(data);
    }

    // لا نعرض الرسالة في الواجهة إلا إذا كانت تنتمي للمحادثة المفتوحة حالياً
    if (targetKey !== currentChatTarget) return;

    feedback.innerHTML = "";

    const messageElement =
        document.createElement('div');

    // تصحيح منطق الرسالة المرسلة: هل المرسل هو المستخدم الحالي؟
    const senderIsMe = data.handle === handle.value || data.handle.includes("خاصة إلى") || data.senderHandle === handle.value;
    
    messageElement.classList.add('chat-message');
    messageElement.classList.add(senderIsMe ? 'sent' : 'received');
    messageElement.setAttribute('data-id', data.id); // تخزين معرف الرسالة في الـ DOM
    
    // إنشاء div لرأس الرسالة (يحتوي على اسم المرسل)
    if (!senderIsMe) {
        const headerWrapper = document.createElement('div');
        headerWrapper.classList.add('chat-header');
        headerWrapper.innerHTML = `<strong>${data.handle}</strong>`;
        messageElement.appendChild(headerWrapper);
    }

    // إنشاء div لمحتوى الرسالة (نص، صورة، فيديو، صوت، ملف)
    const contentWrapper = document.createElement('div');
    contentWrapper.classList.add('chat-content-wrapper');

    let contentElement; // هذا العنصر سيحتوي على الرسالة الفعلية/الوسائط
    if (data.type === 'deleted') {
        contentElement = document.createElement('p');
        contentElement.innerHTML = '<em>🚫 تم مسح هذه الرسالة</em>';
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
        contentElement.alt = "صورة مرسلة"; // إضافة نص بديل لتحسين الوصولية
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
        contentElement.innerText = "📄 " + (data.fileName || "ملف مرفق");
        contentElement.target = "_blank";
        contentElement.style.display = "block";
    }

    // إضافة عنصر المحتوى إلى غلاف المحتوى
    if (contentElement) {
        contentWrapper.appendChild(contentElement);
    }
    messageElement.appendChild(contentWrapper);

    // إضافة زر الحذف إذا كانت الرسالة من المستخدم الحالي وليست ممسوحة مسبقاً
    if (senderIsMe && data.type !== 'deleted' && data.id) {
        const deleteBtn = document.createElement('span');
        deleteBtn.innerHTML = ' 🗑️';
        deleteBtn.style.cursor = 'pointer';
        deleteBtn.style.fontSize = '0.8em';
        deleteBtn.title = 'حذف للجميع';
        deleteBtn.onclick = () => {
            if (confirm('هل تريد حذف هذه الرسالة للجميع؟')) {
                socket.emit('delete-message', { id: data.id });
            }
        };
        contentWrapper.appendChild(deleteBtn);
    }

    // إضافة الوقت والصحين (WhatsApp Style)
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

// استقبال قائمة المستخدمين المتصلين
socket.on('online-users', (users) => {
    onlineUsersList.innerHTML = ''; 

    // إضافة خيار الدردشة العامة دائماً في رأس القائمة
    const generalLi = document.createElement('li');
    generalLi.innerHTML = "<strong>📢 الدردشة العامة</strong>";
    if (currentChatTarget === 'General') generalLi.classList.add('active-chat');
    generalLi.onclick = () => switchChat('General');
    onlineUsersList.appendChild(generalLi);

    users.forEach(userHandle => {
        if (userHandle === handle.value) return; // لا تظهر اسمي لنفسي
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
    currentChatName.innerText = target === 'General' ? "غرفة: General" : "دردشة خاصة مع: " + target;
    document.getElementById('call-actions').style.display = target === 'General' ? 'none' : 'block';
    
    output.innerHTML = ""; // مسح الشاشة لعرض محادثة الهدف الجديد فقط
    (messagesStore[target] || []).forEach(msg => addMessageToUI(msg, false));
    message.focus();
    // إعادة رسم القائمة لتحديث العنصر المختار (Visual Feedback)
    socket.emit('get-online-users'); // طلب تحديث القائمة (اختياري، أو يمكن تحديث الـ CSS يدوياً)
}

// استقبال رسالة جديدة
socket.on('chat', async (data) => {
    if (data.isEncrypted) {
        // التأكد من وجود المفاتيح قبل محاولة فك التشفير
        if (data.handle.includes("خاصة من") && myKeyPair) {
            data.message = await decryptData(data.message, myKeyPair.privateKey);
        } else if (data.handle.includes("خاصة إلى") && encryptionCache.has(data.message)) {
            // استعادة النص الأصلي من الذاكرة المحلية بدلاً من إظهار النص المشفر أو المحجوب
            data.message = encryptionCache.get(data.message);
        }
    }
    addMessageToUI(data);
});

// التعامل مع حذف الرسالة
socket.on('message-deleted', (data) => {
    const msgDiv = document.querySelector(`.chat-message[data-id="${data.id}"]`);
    if (msgDiv) {
        const content = msgDiv.querySelector('.chat-content-wrapper');
        content.innerHTML = '<p style="color: #999;"><em>🚫 تم مسح هذه الرسالة</em></p>';
        // إزالة زر الحذف إن وجد
        const delBtn = msgDiv.querySelector('span');
        if (delBtn) delBtn.remove();
    }
});

// استقبال سجل المحادثات عند الدخول
socket.on('chat-history', async (history) => {
    output.innerHTML = ""; // مسح الشاشة قبل عرض السجل
    messagesStore = { 'General': [] }; // إعادة تهيئة المخزن
    for (const data of history) {
        if (data.isEncrypted && data.handle.includes("خاصة من") && myKeyPair) {
            data.message = await decryptData(data.message, myKeyPair.privateKey);
        } else if (data.isEncrypted && data.handle.includes("خاصة إلى") && encryptionCache.has(data.message)) {
            // استعادة النص الأصلي عند تحميل سجل المحادثات
            data.message = encryptionCache.get(data.message);
        }
        addMessageToUI(data); // سيقوم المخزن بترتيبها وعرض المناسب فقط
    }
});



socket.on('typing', (data) => {

    feedback.innerHTML =
        `<p><em>${data} يكتب...</em></p>`;

});

// --- Voice Call Logic (WebRTC) ---

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
    callStatus.innerText = `جاري الاتصال بـ ${currentChatTarget}...`;
    callOverlay.style.display = 'block';
    acceptCallBtn.style.display = 'none';
};

socket.on('incoming-call', async (data) => {
    currentChatTarget = data.from; // التبديل لمحادثة المتصل تلقائياً
    callStatus.innerText = `مكالمة واردة من ${data.from}`;
    callOverlay.style.display = 'block';
    acceptCallBtn.style.display = 'inline-block';
    
    acceptCallBtn.onclick = async () => {
        await initPeerConnection(data.from);
        await peerConnection.setRemoteDescription(new RTCSessionDescription(data.offer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        
        socket.emit('make-answer', { to: data.from, answer });
        callStatus.innerText = "في مكالمة...";
        acceptCallBtn.style.display = 'none';
    };
});

socket.on('answer-made', async (data) => {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
    callStatus.innerText = "في مكالمة...";
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
    alert("انتهت المكالمة");
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