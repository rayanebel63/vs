const express = require('express');
const http = require('http');
const https = require('https'); // Import HTTPS module
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();

// Read certificate and key files
let server;
try {
    // Attempt to run HTTPS if files exist
    const privateKey = fs.readFileSync(path.join(__dirname, 'key.pem'), 'utf8');
    const certificate = fs.readFileSync(path.join(__dirname, 'cert.pem'), 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    server = https.createServer(credentials, app);
    console.log("🔒 HTTPS server running.");
} catch (e) {
    console.warn("⚠️ HTTPS certificates not found (key.pem, cert.pem). Falling back to HTTP.");
    server = http.createServer(app);
}

const io = new Server(server);

const dbPath = './chat.db';
let db;

// Public keys storage for E2EE
const publicKeys = {};

function initializeDatabase() {
    db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error("❌ Database connection error:", err.message);
            // Attempt to delete corrupted DB and retry
            if (err.code === 'SQLITE_CANTOPEN' || err.code === 'SQLITE_NOTADB') {
                console.error("⚠️ chat.db file might be corrupted or inaccessible. Attempting to re-create...");
                if (fs.existsSync(dbPath)) {
                    try {
                        fs.unlinkSync(dbPath);
                        console.log("✅ Old chat.db removed. Re-initializing database.");
                        initializeDatabase(); // Recursive call to re-initialize
                        return;
                    } catch (unlinkErr) {
                        console.error("❌ Failed to remove corrupted chat.db:", unlinkErr.message);
                    }
                }
            }
            return; // Exit if database connection failed
        }
        console.log("✅ Connected to SQLite database.");

        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            message TEXT,
            handle TEXT,
            fileName TEXT,
            timestamp TEXT,
            isEncrypted INTEGER DEFAULT 0,
            recipientHandle TEXT
        )`, (runErr) => {
                if (runErr) {
                    console.error("❌ Error creating messages table:", runErr.message);
                } else {
                    console.log("✅ Messages table ensured.");
                }
            });
    });
}
initializeDatabase(); // Call it to start
const SECRET_CODE = "2013"; 
let users = {}; 

const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60000; // 1 minute

const uploadDir = './uploads';
try {
    if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir);
        console.log("✅ Upload directory created:", uploadDir);
    }
} catch (err) {
    console.error("❌ Could not create upload directory:", err);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// File upload route
app.post('/upload', upload.single('file'), (req, res) => {
    if (req.file) {
        res.json({ filePath: `/uploads/${req.file.filename}`, originalName: req.file.originalname });
    } else {
        res.status(400).send('File upload failed');
    }
});
io.on('connection', (socket) => {
    // قراءة الـ IP الحقيقي حتى لو كان التطبيق خلف Proxy مثل Render أو Cloudflare
    const clientIp = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;
    socket.authorized = false; // By default, user is not authorized
    console.log(`Server: New connection from ${clientIp}. Socket ID: ${socket.id}`);

    // Verify secret code
    socket.on('verify-code', (code) => {
        const now = Date.now();
        let log = loginAttempts.get(clientIp) || { attempts: 0, lockoutUntil: 0 };

        // Check if IP is currently locked out
        if (log.lockoutUntil > now) {
            const wait = Math.ceil((log.lockoutUntil - now) / 1000);
            console.warn(`Server: IP ${clientIp} is locked out. Remaining: ${wait}s`);
            return socket.emit('auth-result', { success: false, message: `Temporarily blocked. Try again in ${wait} seconds` });
        }

        if (code === SECRET_CODE) {
            console.log(`Server: Socket ${socket.id} authorized.`);
            socket.authorized = true; // Authorize the user
            loginAttempts.delete(clientIp); // Clear failed attempts on success
            socket.emit('auth-result', { success: true });
        } else {
            log.attempts++;
            if (log.attempts >= MAX_ATTEMPTS) {
                log.lockoutUntil = now + LOCKOUT_DURATION;
                console.warn(`Server: Socket ${socket.id} failed auth. IP ${clientIp} locked out.`);
                log.attempts = 0;
                socket.emit('auth-result', { success: false, message: "Login locked for 1 minute after 3 failed attempts" });
            } else {
                socket.emit('auth-result', { success: false, message: `Incorrect code. ${MAX_ATTEMPTS - log.attempts} attempts remaining` });
            }
            loginAttempts.set(clientIp, log);
        }
    });

    // Set username
    socket.on('set-handle', (handle) => {
        console.log(`Server: Received 'set-handle' from ${socket.id}. Handle: ${handle}. Authorized: ${socket.authorized}`);
        if (!socket.authorized) return; // Prevent execution if not authorized

        // Check if name is already taken by another active user
        const isTaken = Object.values(users).some(u => u === handle && users[socket.id] !== handle);
        if (isTaken) {
            console.warn(`Server: Handle '${handle}' is already taken.`);
            return socket.emit('handle-error', 'This name is already taken. Please choose another one.');
        }

        users[socket.id] = handle;
        console.log(`Server: Socket ${socket.id} set handle to '${handle}'. Current online users:`, Object.values(users));
        socket.emit('handle-confirmed', handle); // Notify client that name is accepted
        io.emit('online-users', Object.values(users));

        // Load last 100 messages for the user (public or private)
        db.all("SELECT * FROM messages WHERE recipientHandle IS NULL OR recipientHandle = ? OR handle = ? ORDER BY id DESC LIMIT 100", 
               [handle, handle], (err, rows) => {
            if (err) return;
            const history = rows.reverse().map(row => {
                if (row.recipientHandle) {
                    return {
                        ...row,
                        isEncrypted: !!row.isEncrypted,
                        handle: row.handle === handle ? `(private to ${row.recipientHandle})` : `(private from ${row.handle})`,
                        senderHandle: row.handle
                    };
                }
                return { ...row, isEncrypted: !!row.isEncrypted };
            });
            socket.emit('chat-history', history);
        });
    });

    socket.on('get-online-users', () => {
        if (!socket.authorized) return;
        socket.emit('online-users', Object.values(users));
    });

    // Register user's public key (for encryption)
    socket.on('register-public-key', (data) => {
        console.log(`Server: Received 'register-public-key' for handle: ${data.handle}. Authorized: ${socket.authorized}`);
        if (!socket.authorized) return;
        publicKeys[data.handle] = data.publicKey;
    });

    socket.on('get-public-key', (handle, callback) => {
        console.log(`Server: Received 'get-public-key' request for handle: ${handle}. Authorized: ${socket.authorized}`);
        if (!socket.authorized) return callback(null);
        callback(publicKeys[handle]);
    });

    socket.on('join-room', (room) => {
        if (!socket.authorized) return;
        socket.join(room);
    });

    socket.on('chat', (data) => {
        console.log(`Server: Received 'chat' event from ${socket.id} (${users[socket.id]}). Authorized: ${socket.authorized}. Data:`, data);
        if (!socket.authorized) return;
        data.timestamp = data.timestamp || new Date().toISOString();
        
        db.run("INSERT INTO messages (type, message, handle, fileName, timestamp, isEncrypted) VALUES (?, ?, ?, ?, ?, 0)", 
               [data.type, data.message, data.handle, data.fileName, data.timestamp], function(err) {
            if (err) {
                console.error("❌ Error inserting message into DB:", err.message);
                return;
            }
            data.id = this.lastID; // Get the ID of the newly inserted row
            console.log(`Server: Public message from ${data.handle} broadcasted. ID: ${data.id}`);
            io.emit('chat', data); // Broadcast the message to all connected clients
        });
    });

    socket.on('send-private-message', (data) => {
        console.log(`Server: Received 'send-private-message' from ${socket.id} (${users[socket.id]}) to ${data.recipientHandle}. Authorized: ${socket.authorized}. Data:`, data);
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.recipientHandle);
        if (recipientSocketId) {
            const privateMsg = {
                ...data,
                type: 'text',
                handle: `(private from ${data.senderHandle})`,
                isEncrypted: true 
            };
            db.run("INSERT INTO messages (type, message, handle, timestamp, isEncrypted, recipientHandle) VALUES (?, ?, ?, ?, 1, ?)", 
                   [privateMsg.type, privateMsg.message, privateMsg.senderHandle, privateMsg.timestamp, privateMsg.recipientHandle], function(err) {
                if (err) {
                    console.error("❌ Error inserting private message into DB:", err.message);
                    return;
                }
                privateMsg.id = this.lastID; // Get the ID of the newly inserted row
                console.log(`Server: Private message from ${data.senderHandle} to ${data.recipientHandle} sent. ID: ${privateMsg.id}`);
                io.to(recipientSocketId).emit('chat', privateMsg); // Send to recipient
                socket.emit('chat', { ...privateMsg, handle: `(private to ${data.recipientHandle})` }); // Send to sender
            });
        } else {
            socket.emit('chat', { type: 'text', message: `User ${data.recipientHandle} is not online.`, handle: 'System' });
            console.warn(`Server: Private message to offline user ${data.recipientHandle} from ${data.senderHandle}.`);
        }
    });

    socket.on('delete-message', (data) => {
        if (!socket.authorized) return;
        
        // Only allow sender to delete their own messages
        db.run("UPDATE messages SET type = 'deleted', message = '🚫 This message was deleted' WHERE id = ? AND handle = ?", 
               [data.id, users[socket.id]], function(err) {
            if (err) {
                console.error("❌ Error deleting message from DB:", err.message);
                return;
            }
            if (this.changes > 0) {
                console.log(`Server: Message ID ${data.id} deleted by ${users[socket.id]}.`);
                io.emit('message-deleted', { id: data.id });
            }
        });
    });

    socket.on('clear-history', () => {
        if (!socket.authorized) return;
        db.run("DELETE FROM messages", (err) => {
            if (err) {
                console.error("❌ Error clearing history:", err.message);
            } else {
                console.log("Server: All chat history cleared from DB.");
                io.emit('history-cleared');
            }
        });
    });

    socket.on('call-user', (data) => {
        if (!socket.authorized) return;
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            console.log(`Server: Call initiated from ${users[socket.id]} to ${data.to}.`);
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
            console.log(`Server: Answer made from ${users[socket.id]} to ${data.to}.`);
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
            console.log(`Server: ICE candidate from ${users[socket.id]} to ${data.to}.`);
            io.to(recipientSocketId).emit('ice-candidate', {
                from: users[socket.id],
                candidate: data.candidate
            });
        }
    });

    socket.on('hang-up', (data) => {
        const recipientSocketId = Object.keys(users).find(id => users[id] === data.to);
        if (recipientSocketId) {
            console.log(`Server: Call from ${users[socket.id]} to ${data.to} hung up.`);
            io.to(recipientSocketId).emit('call-ended', { from: users[socket.id] });
        }
    });

    socket.on('typing', (handle) => {
        // console.log(`Server: User ${handle} is typing.`); // Can be noisy, uncomment if needed
        if (!socket.authorized) return;
        socket.broadcast.emit('typing', handle);
    });

    // Clear all active usernames and force clients to reset local data
    socket.on('clear-users', () => {
        if (!socket.authorized) return;
        // 1. Wipe server memory (active sessions)
        Object.keys(users).forEach(id => delete users[id]);
        Object.keys(publicKeys).forEach(handle => delete publicKeys[handle]);
        
        console.log("Server: All active users and public keys cleared.");
        io.emit('online-users', []);
        io.emit('force-reset-local'); // Trigger a full local storage wipe on all clients
    });

    socket.on('disconnect', () => {
        const userHandle = users[socket.id];
        delete users[socket.id];
        if (userHandle) delete publicKeys[userHandle];
        console.log(`Server: Socket ${socket.id} (${userHandle}) disconnected. Remaining online users:`, Object.values(users));
        io.emit('online-users', Object.values(users)); // Update online list for everyone
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    const protocol = server instanceof https.Server ? 'https' : 'http';
    console.log(`Server running on ${protocol}://localhost:${PORT} and on local network.`);
});