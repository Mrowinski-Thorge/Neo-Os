const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'neoos-super-secret-key-2025';

// 🛡️ Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// 💾 SQLite Datenbank
const db = new sqlite3.Database('neoos.db');

// 🗃️ Tabellen erstellen
db.serialize(() => {
    // Benutzer Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        displayName TEXT,
        avatar TEXT,
        color TEXT,
        publicCode TEXT UNIQUE,
        created DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Nachrichten Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        from_user TEXT,
        to_user TEXT,
        content TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Einladungscodes Tabelle
    db.run(`CREATE TABLE IF NOT EXISTS invites (
        code TEXT PRIMARY KEY,
        used BOOLEAN DEFAULT 0
    )`);

    // Standard Einladungscodes hinzufügen
    const codes = ['NEOOS2025', 'WELCOME01', 'BETA001', 'INVITE123', 'START2025'];
    codes.forEach(code => {
        db.run("INSERT OR IGNORE INTO invites (code) VALUES (?)", [code]);
    });
});

// 🔐 Auth Middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Kein Token' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Ungültiger Token' });
    }
};

// 🏠 Homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 💓 Health Check
app.get('/ping', (req, res) => {
    res.json({ 
        status: 'alive', 
        time: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 🎫 Einladungscode prüfen
app.post('/api/check-invite', (req, res) => {
    const { code } = req.body;
    
    db.get("SELECT * FROM invites WHERE code = ? AND used = 0", [code], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Fehler' });
        if (!row) return res.status(400).json({ error: 'Ungültiger Code' });
        
        res.json({ valid: true });
    });
});

// 📝 Registrierung
app.post('/api/register', async (req, res) => {
    const { username, password, displayName, avatar, color, inviteCode } = req.body;
    
    try {
        // Einladungscode prüfen
        db.get("SELECT * FROM invites WHERE code = ? AND used = 0", [inviteCode], async (err, invite) => {
            if (!invite) return res.status(400).json({ error: 'Ungültiger Einladungscode' });
            
            // Passwort hashen
            const hashedPassword = await bcrypt.hash(password, 10);
            const userId = uuidv4();
            const publicCode = 'USER' + Math.random().toString(36).substr(2, 8).toUpperCase();
            
            // Benutzer erstellen
            db.run(`INSERT INTO users (id, username, password, displayName, avatar, color, publicCode)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, username, hashedPassword, displayName, avatar, color, publicCode],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE')) {
                            return res.status(400).json({ error: 'Benutzername bereits vergeben' });
                        }
                        return res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
                    }
                    
                    // Einladungscode als verwendet markieren
                    db.run("UPDATE invites SET used = 1 WHERE code = ?", [inviteCode]);
                    
                    // JWT Token erstellen
                    const token = jwt.sign({ userId }, JWT_SECRET);
                    
                    res.json({
                        message: 'Registrierung erfolgreich',
                        token,
                        user: {
                            id: userId,
                            username,
                            displayName,
                            avatar,
                            color,
                            publicCode
                        }
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Server Fehler' });
    }
});

// 🔑 Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'DB Fehler' });
        if (!user) return res.status(400).json({ error: 'Benutzer nicht gefunden' });
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Falsches Passwort' });
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        
        res.json({
            message: 'Login erfolgreich',
            token,
            user: {
                id: user.id,
                username: user.username,
                displayName: user.displayName,
                avatar: user.avatar,
                color: user.color,
                publicCode: user.publicCode
            }
        });
    });
});

// 👤 Benutzer finden
app.post('/api/find-user', authenticate, (req, res) => {
    const { publicCode } = req.body;
    
    db.get("SELECT id, username, displayName, avatar, color, publicCode FROM users WHERE publicCode = ?", 
        [publicCode], (err, user) => {
            if (err) return res.status(500).json({ error: 'DB Fehler' });
            if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden' });
            
            res.json({ user });
        });
});

// 💬 Nachricht senden
app.post('/api/send-message', authenticate, (req, res) => {
    const { toUser, content } = req.body;
    const messageId = uuidv4();
    
    db.run("INSERT INTO messages (id, from_user, to_user, content) VALUES (?, ?, ?, ?)",
        [messageId, req.userId, toUser, content], function(err) {
            if (err) return res.status(500).json({ error: 'Nachricht senden fehlgeschlagen' });
            
            res.json({ 
                message: 'Nachricht gesendet',
                id: messageId
            });
        });
});

// 📬 Nachrichten abrufen
app.get('/api/messages/:contactId', authenticate, (req, res) => {
    const { contactId } = req.params;
    
    db.all(`SELECT m.*, u.displayName as senderName, u.avatar as senderAvatar 
            FROM messages m 
            JOIN users u ON m.from_user = u.id 
            WHERE (m.from_user = ? AND m.to_user = ?) 
               OR (m.from_user = ? AND m.to_user = ?)
            ORDER BY m.created ASC`,
        [req.userId, contactId, contactId, req.userId], (err, messages) => {
            if (err) return res.status(500).json({ error: 'DB Fehler' });
            
            res.json({ messages });
        });
});

// 📋 Kontakte abrufen
app.get('/api/contacts', authenticate, (req, res) => {
    db.all(`SELECT DISTINCT u.id, u.username, u.displayName, u.avatar, u.color, u.publicCode,
                   (SELECT content FROM messages 
                    WHERE (from_user = u.id AND to_user = ?) 
                       OR (from_user = ? AND to_user = u.id)
                    ORDER BY created DESC LIMIT 1) as lastMessage
            FROM users u 
            WHERE EXISTS (
                SELECT 1 FROM messages m 
                WHERE (m.from_user = u.id AND m.to_user = ?) 
                   OR (m.from_user = ? AND m.to_user = u.id)
            ) AND u.id != ?`,
        [req.userId, req.userId, req.userId, req.userId, req.userId], (err, contacts) => {
            if (err) return res.status(500).json({ error: 'DB Fehler' });
            
            res.json({ contacts });
        });
});

// 📊 System Status
app.get('/api/status', authenticate, (req, res) => {
    db.get("SELECT COUNT(*) as userCount FROM users", (err, userCount) => {
        db.get("SELECT COUNT(*) as messageCount FROM messages", (err2, messageCount) => {
            res.json({
                server: 'online',
                users: userCount?.userCount || 0,
                messages: messageCount?.messageCount || 0,
                uptime: process.uptime()
            });
        });
    });
});

// 🚀 Server starten
app.listen(PORT, () => {
    console.log(`🧠 NeoOS Server läuft auf Port ${PORT}`);
    console.log(`🌐 Frontend: http://localhost:${PORT}`);
    console.log(`🔗 API: http://localhost:${PORT}/api`);
    console.log(`💓 Health: http://localhost:${PORT}/ping`);
    
    // Keep-alive für Render.com
    if (process.env.NODE_ENV === 'production') {
        setInterval(() => {
            console.log('💓 Keep alive ping');
        }, 5 * 60 * 1000);
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Server wird beendet...');
    db.close();
    process.exit(0);
});
