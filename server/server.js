const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'neoos-render-secret-key-2025';

// 🛡️ CORS für GitHub Pages konfigurieren
app.use(cors({
    origin: [
        'https://mrowinski-thorge.github.io',  // Deine GitHub Pages Domain
        'http://localhost:3000',              // Lokale Entwicklung
        'http://localhost:3001'               // Lokaler Server
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// 💾 SQLite Datenbank (Render persistent disk)
const dbPath = process.env.NODE_ENV === 'production' 
    ? '/opt/render/project/src/database/neoos.db'  // Render persistent path
    : './neoos.db';

const db = new sqlite3.Database(dbPath);

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
    
    console.log('✅ Datenbank initialisiert');
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

// 🏠 Root Route
app.get('/', (req, res) => {
    res.json({ 
        message: 'NeoOS Backend Server',
        status: 'online',
        frontend: 'https://mrowinski-thorge.github.io/Neo-Os',
        api: 'https://neo-os.onrender.com/api',
        version: '1.0.0'
    });
});

// 💓 Health Check
app.get('/ping', (req, res) => {
    res.json({ 
        status: 'alive', 
        time: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        database: 'connected'
    });
});

// 🎫 Einladungscode prüfen
app.post('/api/check-invite', (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'Einladungscode erforderlich' });
    }
    
    db.get("SELECT * FROM invites WHERE code = ? AND used = 0", [code], (err, row) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Datenbankfehler' });
        }
        if (!row) {
            return res.status(400).json({ error: 'Ungültiger oder bereits verwendeter Code' });
        }
        
        res.json({ valid: true });
    });
});

// 📝 Registrierung
app.post('/api/register', async (req, res) => {
    const { username, password, displayName, avatar, color, inviteCode } = req.body;
    
    if (!username || !password || !displayName || !inviteCode) {
        return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
    }
    
    try {
        // Einladungscode prüfen
        db.get("SELECT * FROM invites WHERE code = ? AND used = 0", [inviteCode], async (err, invite) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            if (!invite) {
                return res.status(400).json({ error: 'Ungültiger Einladungscode' });
            }
            
            // Passwort hashen
            const hashedPassword = await bcrypt.hash(password, 12);
            const userId = uuidv4();
            const publicCode = 'USER' + Math.random().toString(36).substr(2, 8).toUpperCase();
            
            // Benutzer erstellen
            db.run(`INSERT INTO users (id, username, password, displayName, avatar, color, publicCode)
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [userId, username, hashedPassword, displayName, avatar || '😊', color || '#007AFF', publicCode],
                function(err) {
                    if (err) {
                        console.error('User creation error:', err);
                        if (err.message.includes('UNIQUE')) {
                            return res.status(400).json({ error: 'Benutzername bereits vergeben' });
                        }
                        return res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
                    }
                    
                    // Einladungscode als verwendet markieren
                    db.run("UPDATE invites SET used = 1 WHERE code = ?", [inviteCode]);
                    
                    // JWT Token erstellen
                    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '30d' });
                    
                    console.log(`✅ Neuer Benutzer registriert: ${username} (${publicCode})`);
                    
                    res.status(201).json({
                        message: 'Registrierung erfolgreich',
                        token,
                        user: {
                            id: userId,
                            username,
                            displayName,
                            avatar: avatar || '😊',
                            color: color || '#007AFF',
                            publicCode
                        }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server Fehler' });
    }
});

// 🔑 Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
    }
    
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Datenbankfehler' });
        }
        if (!user) {
            return res.status(400).json({ error: 'Benutzer nicht gefunden' });
        }
        
        try {
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(400).json({ error: 'Falsches Passwort' });
            }
            
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
            
            console.log(`✅ Benutzer angemeldet: ${username}`);
            
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
        } catch (error) {
            console.error('Password comparison error:', error);
            res.status(500).json({ error: 'Anmeldung fehlgeschlagen' });
        }
    });
});

// 👤 Benutzer finden
app.post('/api/find-user', authenticate, (req, res) => {
    const { publicCode } = req.body;
    
    if (!publicCode) {
        return res.status(400).json({ error: 'Öffentlicher Code erforderlich' });
    }
    
    db.get("SELECT id, username, displayName, avatar, color, publicCode FROM users WHERE publicCode = ? AND id != ?", 
        [publicCode, req.userId], (err, user) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            if (!user) {
                return res.status(404).json({ error: 'Benutzer nicht gefunden' });
            }
            
            res.json({ user });
        });
});

// 💬 Nachricht senden
app.post('/api/send-message', authenticate, (req, res) => {
    const { toUser, content } = req.body;
    
    if (!toUser || !content) {
        return res.status(400).json({ error: 'Empfänger und Nachricht erforderlich' });
    }
    
    const messageId = uuidv4();
    
    db.run("INSERT INTO messages (id, from_user, to_user, content) VALUES (?, ?, ?, ?)",
        [messageId, req.userId, toUser, content], function(err) {
            if (err) {
                console.error('Message send error:', err);
                return res.status(500).json({ error: 'Nachricht senden fehlgeschlagen' });
            }
            
            console.log(`📤 Nachricht gesendet: ${req.userId} -> ${toUser}`);
            
            res.json({ 
                message: 'Nachricht gesendet',
                id: messageId
            });
        });
});

// 📬 Nachrichten abrufen
app.get('/api/messages/:contactId', authenticate, (req, res) => {
    const { contactId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    db.all(`SELECT m.*, u.displayName as senderName, u.avatar as senderAvatar 
            FROM messages m 
            JOIN users u ON m.from_user = u.id 
            WHERE (m.from_user = ? AND m.to_user = ?) 
               OR (m.from_user = ? AND m.to_user = ?)
            ORDER BY m.created ASC
            LIMIT ? OFFSET ?`,
        [req.userId, contactId, contactId, req.userId, limit, offset], (err, messages) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            
            res.json({ messages });
        });
});

// 📋 Kontakte abrufen
app.get('/api/contacts', authenticate, (req, res) => {
    db.all(`SELECT DISTINCT u.id, u.username, u.displayName, u.avatar, u.color, u.publicCode,
                   (SELECT content FROM messages 
                    WHERE (from_user = u.id AND to_user = ?) 
                       OR (from_user = ? AND to_user = u.id)
                    ORDER BY created DESC LIMIT 1) as lastMessage,
                   (SELECT created FROM messages 
                    WHERE (from_user = u.id AND to_user = ?) 
                       OR (from_user = ? AND to_user = u.id)
                    ORDER BY created DESC LIMIT 1) as lastMessageTime
            FROM users u 
            WHERE EXISTS (
                SELECT 1 FROM messages m 
                WHERE (m.from_user = u.id AND m.to_user = ?) 
                   OR (m.from_user = ? AND m.to_user = u.id)
            ) AND u.id != ?
            ORDER BY lastMessageTime DESC`,
        [req.userId, req.userId, req.userId, req.userId, req.userId, req.userId, req.userId], (err, contacts) => {
            if (err) {
                console.error('DB Error:', err);
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            
            res.json({ contacts });
        });
});

// 📊 System Status
app.get('/api/status', authenticate, (req, res) => {
    db.get("SELECT COUNT(*) as userCount FROM users", (err, userCount) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Datenbankfehler' });
        }
        
        db.get("SELECT COUNT(*) as messageCount FROM messages", (err2, messageCount) => {
            if (err2) {
                console.error('DB Error:', err2);
                return res.status(500).json({ error: 'Datenbankfehler' });
            }
            
            db.get("SELECT COUNT(*) as unusedCodes FROM invites WHERE used = 0", (err3, unusedCodes) => {
                if (err3) {
                    console.error('DB Error:', err3);
                    return res.status(500).json({ error: 'Datenbankfehler' });
                }
                
                res.json({
                    server: 'online',
                    users: userCount?.userCount || 0,
                    messages: messageCount?.messageCount || 0,
                    availableInvites: unusedCodes?.unusedCodes || 0,
                    uptime: process.uptime(),
                    environment: process.env.NODE_ENV || 'development',
                    version: '1.0.0'
                });
            });
        });
    });
});

// 🛠️ Admin Route - Neue Einladungscodes erstellen
app.post('/api/admin/create-invite', authenticate, (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'Code erforderlich' });
    }
    
    db.run("INSERT INTO invites (code) VALUES (?)", [code], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(400).json({ error: 'Code bereits vorhanden' });
            }
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Datenbankfehler' });
        }
        
        console.log(`✅ Neuer Einladungscode erstellt: ${code}`);
        res.json({ message: 'Einladungscode erstellt', code });
    });
});

// 🚫 404 Handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Endpoint nicht gefunden',
        available: {
            api: '/api',
            health: '/ping',
            frontend: 'https://mrowinski-thorge.github.io/Neo-Os'
        }
    });
});

// 🚨 Error Handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Interner Server Fehler' });
});

// 🚀 Server starten
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('🧠 NeoOS Backend Server gestartet!');
    console.log(`📡 Port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  Datenbank: ${dbPath}`);
    console.log(`🌐 Frontend: https://mrowinski-thorge.github.io/Neo-Os`);
    console.log(`🔗 API Base: https://neo-os.onrender.com/api`);
    console.log(`💓 Health Check: https://neo-os.onrender.com/ping`);
});

// 💓 Keep-alive für Render.com (verhindert Sleep)
if (process.env.NODE_ENV === 'production') {
    setInterval(() => {
        console.log(`💓 Keep-alive ping - ${new Date().toISOString()}`);
        
        // Selbst-Ping um Server wach zu halten
        fetch('https://neo-os.onrender.com/ping')
            .catch(err => console.log('Keep-alive ping failed:', err.message));
    }, 5 * 60 * 1000); // Alle 5 Minuten
}

// 🛑 Graceful Shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Server wird beendet...');
    
    db.close((err) => {
        if (err) {
            console.error('Fehler beim Schließen der Datenbank:', err.message);
        } else {
            console.log('💾 Datenbank geschlossen');
        }
    });
    
    server.close(() => {
        console.log('🚪 Server beendet');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM empfangen, beende Server...');
    
    db.close();
    server.close(() => {
        process.exit(0);
    });
});
