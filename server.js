const express = require('express');
const http = require('http');
const https = require('https'); 
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();

let server;
try {
    
    const privateKey = fs.readFileSync(path.join(__dirname, 'key.pem'), 'utf8');
    const certificate = fs.readFileSync(path.join(__dirname, 'cert.pem'), 'utf8');
    const credentials = { key: privateKey, cert: certificate };
    server = https.createServer(credentials, app);
    console.log("🔒 HTTPS server running.");
} catch (e) {
    console.warn("⚠️ HTTPS certificates not found (key.pem, cert.pem). Falling back to HTTP.");
    server = http.createServer(app);
}

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling'] 
});

const dbPath = './chat.db';
let db;


const publicKeys = {};

function initializeDatabase() {
    db = new sqlite3.Database(dbPath, (err) => {
        if (err) {
            console.error("❌ Database connection error:", err.message);
           
            if (err.code === 'SQLITE_CANTOPEN' || err.code === 'SQLITE_NOTADB') {
                console.error("⚠️ chat.db file might be corrupted or inaccessible. Attempting to re-create...");
                if (fs.existsSync(dbPath)) {
                    try {
                        fs.unlinkSync(dbPath);
                        console.log("✅ Old chat.db removed. Re-initializing database.");
                        initializeDatabase(); 
                        return;
                    } catch (unlinkErr) {
                        console.error("❌ Failed to remove corrupted chat.db:", unlinkErr.message);
                    }
                }
            }
            return;
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
initializeDatabase(); 
const SECRET_CODE = "2013"; 
let users = {}; 

const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 60000; 

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


app.post('/upload', upload.single('file'), (req, res) => {
    if (req.file) {
        res.json({ filePath: `/uploads/${req.file.filename}`, originalName: req.file.originalname });
    } else {
        res.status(400).send('File upload failed');
    }
});
io.on('connection', (socket) => {
    
    const forwarded = socket.handshake.headers['x-forwarded-for'];
    const clientIp = forwarded ? forwarded.split(',')[0].trim() : socket.handshake.address;
    socket.authorized = false; 
    console.log(`Server: New connection from ${clientIp}. Socket ID: ${socket.id}`);

    
    socket.on('verify-code', (code) => {
        const now = Date.now();
        let log = loginAttempts.get(clientIp) || { attempts: 0, lockoutUntil: 0 };

        
        if (log.lockoutUntil > now) {
            const wait = Math.ceil((log.lockoutUntil - now) / 1000);
            console.warn(`Server: IP ${clientIp} is locked out. Remaining: ${wait}s`);
            return socket.emit('auth-result', { success: false, message: `Temporarily blocked. Try again in ${wait} seconds` });
        }

        if (code === SECRET_CODE) {
            console.log(`Server: Socket ${socket.id} authorized.`);
            socket.authorized = true; 
            loginAttempts.delete(clientIp); 
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

    
    socket.on('set-handle', (handle) => {
        console.log(`Server: Received 'set-handle' from ${socket.id}. Handle: ${handle}. Authorized: ${socket.authorized}`);
        if (!socket.authorized) return; 

       
        const isTaken = Object.values(users).some(u => u === handle && users[socket.id] !== handle);
        if (isTaken) {
            console.warn(`Server: Handle '${handle}' is already taken.`);
            return socket.emit('handle-error', 'This name is already taken. Please choose another one.');
        }

        users[socket.id] = handle;
        console.log(`Server: Socket ${socket.id} set handle to '${handle}'. Current online users:`, Object.values(users));
        socket.emit('handle-confirmed', handle); 
        io.emit('online-users', Object.values(users));

       
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
            data.id = this.lastID; 
            console.log(`Server: Public message from ${data.handle} broadcasted. ID: ${data.id}`);
            io.emit('chat', data); 
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
                privateMsg.id = this.lastID; 
                console.log(`Server: Private message from ${data.senderHandle} to ${data.recipientHandle} sent. ID: ${privateMsg.id}`);
                io.to(recipientSocketId).emit('chat', privateMsg); 
                socket.emit('chat', { ...privateMsg, handle: `(private to ${data.recipientHandle})` }); 
            });
        } else {
            socket.emit('chat', { type: 'text', message: `User ${data.recipientHandle} is not online.`, handle: 'System' });
            console.warn(`Server: Private message to offline user ${data.recipientHandle} from ${data.senderHandle}.`);
        }
    });

    socket.on('delete-message', (data) => {
        if (!socket.authorized) return;
        
       
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
        
        if (!socket.authorized) return;
        socket.broadcast.emit('typing', handle);
    });

    
    socket.on('clear-users', () => {
        if (!socket.authorized) return;
        
        Object.keys(users).forEach(id => delete users[id]);
        Object.keys(publicKeys).forEach(handle => delete publicKeys[handle]);
        
        console.log("Server: All active users and public keys cleared.");
        io.emit('online-users', []);
        io.emit('force-reset-local'); 
    });

    socket.on('disconnect', () => {
        const userHandle = users[socket.id];
        delete users[socket.id];
        if (userHandle) delete publicKeys[userHandle];
        console.log(`Server: Socket ${socket.id} (${userHandle}) disconnected. Remaining online users:`, Object.values(users));
        io.emit('online-users', Object.values(users)); 
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    const protocol = server instanceof https.Server ? 'https' : 'http';
    console.log(`Server running on ${protocol}://localhost:${PORT} and on local network.`);
});
