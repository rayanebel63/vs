const express = require('express');
const http = require('http');
const https = require('https'); // استيراد وحدة HTTPS
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// قراءة ملفات الشهادة والمفتاح
const privateKey = fs.readFileSync('key.pem', 'utf8');
const certificate = fs.readFileSync('cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };
const server = https.createServer(credentials, app); // إنشاء خادم HTTPS
const io = new Server(server);

const dbPath = './chat.db';
let db;

// إعداد قاعدة البيانات وتجهيز الجدول
function initializeDatabase() {
    db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error("❌ خطأ في الاتصال بقاعدة البيانات:", err.message);
        } else {
            console.log("✅ متصل بقاعدة البيانات SQLite.");
            
            // محاولة إنشاء الجدول وفحص صحة الملف
            db.run(`CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                message TEXT,
                handle TEXT,
                fileName TEXT,
                timestamp TEXT,
                isEncrypted INTEGER,
                recipientHandle TEXT
            )`, (runErr) => {
                if (runErr) {
                    if (runErr.code === 'SQLITE_NOTADB') {
                        console.error("⚠️ ملف chat.db تالف. يتم حذفه وإعادة إنشائه...");
                        db.close(() => {
                            if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
                            initializeDatabase(); // إعادة المحاولة بعد الحذف
                        });
                    } else {
                        console.error("❌ خطأ في قاعدة البيانات:", runErr.message);
                    }
                }
            });
        }
    });
}
initializeDatabase();

const SECRET_CODE = "2013"; // الكود السري الافتراضي
let users = {}; // لتتبع المستخدمين { socketId: handle }
let publicKeys = {}; // لتخزين المفاتيح العامة للتشفير { handle: publicKey }

// تتبع محاولات الدخول الخاطئة بناءً على الـ IP في ذاكرة الخادم
const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60000; // دقيقة واحدة

// التأكد من وجود مجلد الرفع لتجنب الأخطاء
const uploadDir = './uploads';
try {
    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir);
    }
} catch (err) {
    console.error("تعذر إنشاء مجلد الرفع:", err);
}

// إعداد Multer لتخزين الملفات
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// مسار رفع الملفات
app.post('/upload', upload.single('file'), (req, res) => {
    if (req.file) {
        res.json({ filePath: `/uploads/${req.file.filename}`, originalName: req.file.originalname });
    } else {
        res.status(400).send('فشل رفع الملف');
    }
});

io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    socket.authorized = false; // افتراضياً، المستخدم غير موثق

    // التحقق من الكود السري
    socket.on('verify-code', (code) => {
        const now = Date.now();
        const log = loginAttempts.get(clientIp) || { attempts: 0, lockoutUntil: 0 };

        // التحقق مما إذا كان الـ IP محظوراً حالياً
        if (log.lockoutUntil > now) {
            const wait = Math.ceil((log.lockoutUntil - now) / 1000);
            return socket.emit('auth-result', { success: false, message: `محظور مؤقتاً. حاول بعد ${wait} ثانية` });
        }

        if (code === SECRET_CODE) {
            socket.authorized = true;
            loginAttempts.delete(clientIp); // مسح سجل المحاولات الفاشلة عند النجاح
            socket.emit('auth-result', { success: true });
        } else {
            log.attempts++;
            if (log.attempts >= MAX_ATTEMPTS) {
                log.lockoutUntil = now + LOCKOUT_DURATION;
                log.attempts = 0;
                socket.emit('auth-result', { success: false, message: "تم قفل الدخول لمدة دقيقة بعد 3 محاولات خاطئة" });
            } else {
                socket.emit('auth-result', { success: false, message: `كود خاطئ. تبقى لك ${MAX_ATTEMPTS - log.attempts} محاولات` });
            }
            loginAttempts.set(clientIp, log);
        }
    });

    // إعداد اسم المستخدم
    socket.on('set-handle', (handle) => {
        if (!socket.authorized) return; // منع التنفيذ إذا لم يتم التحقق
        users[socket.id] = handle;
        io.emit('online-users', Object.values(users));

        // تحميل آخر 100 رسالة تخص المستخدم (عامة أو خاصة به)
        db.all("SELECT * FROM messages WHERE recipientHandle IS NULL OR recipientHandle = ? OR handle = ? ORDER BY id DESC LIMIT 100", 
               [handle, handle], (err, rows) => {
            if (err) return;
            const history = rows.reverse().map(row => {
                if (row.recipientHandle) {
                    return {
                        ...row,
                        isEncrypted: !!row.isEncrypted,
                        handle: row.handle === handle ? `(خاصة إلى ${row.recipientHandle})` : `(خاصة من ${row.handle})`,
                        senderHandle: row.handle
                    };
                }
                return { ...row, isEncrypted: !!row.isEncrypted };
            });
            socket.emit('chat-history', history);
        });
    });

    // تحديث قائمة المستخدمين عند الطلب
    socket.on('get-online-users', () => {
        if (!socket.authorized) return;
        socket.emit('online-users', Object.values(users));
    });

    // تسجيل المفتاح العام للمستخدم (للتشفير)
    socket.on('register-public-key', (data) => {
        if (!socket.authorized) return;
        publicKeys[data.handle] = data.publicKey;
    });

    // طلب المفتاح العام لمستخدم معين
    socket.on('get-public-key', (handle, callback) => {
        if (!socket.authorized) return callback(null);
        callback(publicKeys[handle]);
    });

    // الانضمام لغرفة
    socket.on('join-room', (room) => {
        if (!socket.authorized) return;
        socket.join(room);
    });

    // إرسال رسالة عامة
    socket.on('chat', (data) => {
        if (!socket.authorized) return;
        data.timestamp = data.timestamp || new Date().toISOString();
        
        db.run("INSERT INTO messages (type, message, handle, fileName, timestamp, isEncrypted) VALUES (?, ?, ?, ?, ?, 0)", 
               [data.type, data.message, data.handle, data.fileName, data.timestamp], function(err) {
            if (err) return;
            data.id = this.lastID; // إضافة المعرف الفريد للرسالة
            io.emit('chat', data);
        });
    });

    // إرسال رسالة خاصة
    socket.on('send-private-message', (data) => {
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.recipientHandle);
        if (recipientSocketId) {
            const privateMsg = {
                ...data,
                type: 'text',
                handle: `(خاصة من ${data.senderHandle})`,
                isEncrypted: true // وسم الرسالة كمشفرة
            };

            db.run("INSERT INTO messages (type, message, handle, timestamp, isEncrypted, recipientHandle) VALUES ('text', ?, ?, ?, 1, ?)", 
                   [data.message, data.senderHandle, data.timestamp, data.recipientHandle], function(err) {
                if (err) return;
                privateMsg.id = this.lastID;
                io.to(recipientSocketId).emit('chat', privateMsg);
                socket.emit('chat', { ...privateMsg, handle: `(خاصة إلى ${data.recipientHandle})` });
            });
        }
    });

    // حذف الرسالة للجميع
    socket.on('delete-message', (data) => {
        if (!socket.authorized) return;
        
        // التحقق أن القائم بالحذف هو صاحب الرسالة الأصلي
        db.run("UPDATE messages SET message = 'تم مسح هذه الرسالة', type = 'deleted' WHERE id = ? AND handle = ?", 
               [data.id, users[socket.id]], function(err) {
            if (err) return;
            if (this.changes > 0) {
                io.emit('message-deleted', { id: data.id });
            }
        });
    });

    // --- Signaling for Voice Calls ---
    socket.on('call-user', (data) => {
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('incoming-call', {
                from: users[socket.id],
                offer: data.offer
            });
        }
    });

    socket.on('make-answer', (data) => {
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('answer-made', {
                from: users[socket.id],
                answer: data.answer
            });
        }
    });

    socket.on('ice-candidate', (data) => {
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('ice-candidate', {
                from: users[socket.id],
                candidate: data.candidate
            });
        }
    });

    socket.on('hang-up', (data) => {
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('call-ended', { from: users[socket.id] });
        }
    });

    // التنبيه عند الكتابة
    socket.on('typing', (handle) => {
        if (!socket.authorized) return;
        socket.broadcast.emit('typing', handle);
    });

    socket.on('disconnect', () => {
        const userHandle = users[socket.id];
        delete users[socket.id];
        if (userHandle) delete publicKeys[userHandle];

        io.emit('online-users', Object.values(users));
    });
});

const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`الخادم يعمل على https://localhost:${PORT} وعلى الشبكة المحلية`);
});