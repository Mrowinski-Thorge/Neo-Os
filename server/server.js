const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

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

// 🐘 PostgreSQL Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 🗃️ Tabellen erstellen
async function initDatabase() {
    const client = await pool.connect();
    
    try {
        // Benutzer Tabelle
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                display_name TEXT NOT NULL,
                avatar TEXT DEFAULT '😊',
                color TEXT DEFAULT '#007AFF',
                public_code TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Nachrichten Tabelle
        await client.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_user) REFERENCES users (id),
                FOREIGN KEY (to_user) REFERENCES users (id)
            )
        `);

        // Einladungscodes Tabelle
        await client.query(`
            CREATE TABLE IF NOT EXISTS invites (
                code TEXT PRIMARY KEY,
                used BOOLEAN DEFAULT FALSE,
                used_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (used_by) REFERENCES users (id)
            )
        `);

        // Standard Einladungscodes hinzufügen
        const codes = ['NEOOS2025', 'WELCOME01', 'BETA001', 'INVITE123', 'START2025'];
        for (const code of codes) {
            await client.query(
                'INSERT INTO invites (code) VALUES ($1) ON CONFLICT (code) DO NOTHING',
                [code]
            );
        }
        
        console.log('✅ PostgreSQL Datenbank initialisiert');
    } catch (error) {
        console.error('❌ Fehler bei Datenbankinitialisierung:', error);
    } finally {
        client.release();
    }
}

// 🔐 Auth Middleware
const authenticate = async (req, res, next) => {
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
        message: 'NeoOS Backend Server with PostgreSQL',
        status: 'online',
        frontend: 'https://mrowinski-thorge.github.io/Neo-Os',
        api: 'https://neo-os.onrender.com/api',
        database: 'PostgreSQL',
        version: '1.0.0'
    });
});

// 💓 Health Check
app.get('/ping', async (req, res) => {
    try {
        // Database connectivity test
        const result = await pool.query('SELECT NOW()');
        
        res.json({ 
            status: 'alive', 
            time: new Date().toISOString(),
            uptime: process.uptime(),
            environment: process.env.NODE_ENV || 'development',
            database: 'connected',
            dbTime: result.rows[0].now
        });
    } catch (error) {
        console.error('Health check error:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: 'Database connection failed'
        });
    }
});

// 🎫 Einladungscode prüfen
app.post('/api/check-invite', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'Einladungscode erforderlich' });
    }
    
    try {
        const result = await pool.query(
            'SELECT * FROM invites WHERE code = $1 AND used = FALSE',
            [code]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Ungültiger oder bereits verwendeter Code' });
        }
        
        res.json({ valid: true });
    } catch (error) {
        console.error('DB Error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
});

// 📝 Registrierung
app.post('/api/register', async (req, res) => {
    const { username, password, displayName, avatar, color, inviteCode } = req.body;
    
    if (!username || !password || !displayName || !inviteCode) {
        return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
    }
    
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        // Einladungscode prüfen
        const inviteResult = await client.query(
            'SELECT * FROM invites WHERE code = $1 AND used = FALSE',
            [inviteCode]
        );
        
        if (inviteResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Ungültiger Einladungscode' });
        }
        
        // Prüfen ob Benutzername bereits existiert
        const userCheck = await client.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        
        if (userCheck.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Benutzername bereits vergeben' });
        }
        
        // Passwort hashen
        const hashedPassword = await bcrypt.hash(password, 12);
        const userId = uuidv4();
        const publicCode = 'USER' + Math.random().toString(36).substr(2, 8).toUpperCase();
        
        // Benutzer erstellen
        await client.query(
            `INSERT INTO users (id, username, password, display_name, avatar, color, public_code)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [userId, username, hashedPassword, displayName, avatar || '😊', color || '#007AFF', publicCode]
        );
        
        // Einladungscode als verwendet markieren
        await client.query(
            'UPDATE invites SET used = TRUE, used_by = $1 WHERE code = $2',
            [userId, inviteCode]
        );
        
        await client.query('COMMIT');
        
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
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registrierung fehlgeschlagen' });
    } finally {
        client.release();
    }
});

// 🔑 Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Benutzername und Passwort erforderlich' });
    }
    
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Benutzer nicht gefunden' });
        }
        
        const user = result.rows[0];
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
                displayName: user.display_name,
                avatar: user.avatar,
                color: user.color,
                publicCode: user.public_code
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Anmeldung fehlgeschlagen' });
    }
});

// 👤 Benutzer finden
app.post('/api/find-user', authenticate, async (req, res) => {
    const { publicCode } = req.body;
    
    if (!publicCode) {
        return res.status(400).json({ error: 'Öffentlicher Code erforderlich' });
    }
    
    try {
        const result = await pool.query(
            'SELECT id, username, display_name, avatar, color, public_code FROM users WHERE public_code = $1 AND id != $2',
            [publicCode, req.userId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Benutzer nicht gefunden' });
        }
        
        const user = result.rows[0];
        res.json({ 
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                avatar: user.avatar,
                color: user.color,
                publicCode: user.public_code
            }
        });
    } catch (error) {
        console.error('Find user error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
});

// 💬 Nachricht senden
app.post('/api/send-message', authenticate, async (req, res) => {
    const { toUser, content } = req.body;
    
    if (!toUser || !content) {
        return res.status(400).json({ error: 'Empfänger und Nachricht erforderlich' });
    }
    
    try {
        const messageId = uuidv4();
        
        await pool.query(
            'INSERT INTO messages (id, from_user, to_user, content) VALUES ($1, $2, $3, $4)',
            [messageId, req.userId, toUser, content]
        );
        
        console.log(`📤 Nachricht gesendet: ${req.userId} -> ${toUser}`);
        
        res.json({ 
            message: 'Nachricht gesendet',
            id: messageId
        });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: 'Nachricht senden fehlgeschlagen' });
    }
});

// 📬 Nachrichten abrufen
app.get('/api/messages/:contactId', authenticate, async (req, res) => {
    const { contactId } = req.params;
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    try {
        const result = await pool.query(`
            SELECT m.*, u.display_name as sender_name, u.avatar as sender_avatar 
            FROM messages m 
            JOIN users u ON m.from_user = u.id 
            WHERE (m.from_user = $1 AND m.to_user = $2) 
               OR (m.from_user = $2 AND m.to_user = $1)
            ORDER BY m.created_at ASC
            LIMIT $3 OFFSET $4
        `, [req.userId, contactId, limit, offset]);
        
        res.json({ messages: result.rows });
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
});

// 📋 Kontakte abrufen
app.get('/api/contacts', authenticate, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT u.id, u.username, u.display_name, u.avatar, u.color, u.public_code,
                   (SELECT content FROM messages 
                    WHERE (from_user = u.id AND to_user = $1) 
                       OR (from_user = $1 AND to_user = u.id)
                    ORDER BY created_at DESC LIMIT 1) as last_message,
                   (SELECT created_at FROM messages 
                    WHERE (from_user = u.id AND to_user = $1) 
                       OR (from_user = $1 AND to_user = u.id)
                    ORDER BY created_at DESC LIMIT 1) as last_message_time
            FROM users u 
            WHERE EXISTS (
                SELECT 1 FROM messages m 
                WHERE (m.from_user = u.id AND m.to_user = $1) 
                   OR (m.from_user = $1 AND m.to_user = u.id)
            ) AND u.id != $1
            ORDER BY last_message_time DESC
        `, [req.userId]);
        
        const contacts = result.rows.map(row => ({
            id: row.id,
            username: row.username,
            displayName: row.display_name,
            avatar: row.avatar,
            color: row.color,
            publicCode: row.public_code,
            lastMessage: row.last_message,
            lastMessageTime: row.last_message_time
        }));
        
        res.json({ contacts });
    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
});

// 📊 System Status
app.get('/api/status', authenticate, async (req, res) => {
    try {
        const userCountResult = await pool.query('SELECT COUNT(*) as count FROM users');
        const messageCountResult = await pool.query('SELECT COUNT(*) as count FROM messages');
        const unusedCodesResult = await pool.query('SELECT COUNT(*) as count FROM invites WHERE used = FALSE');
        
        res.json({
            server: 'online',
            users: parseInt(userCountResult.rows[0].count),
            messages: parseInt(messageCountResult.rows[0].count),
            availableInvites: parseInt(unusedCodesResult.rows[0].count),
            uptime: process.uptime(),
            environment: process.env.NODE_ENV || 'development',
            database: 'PostgreSQL',
            version: '1.0.0'
        });
    } catch (error) {
        console.error('Status error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
});

// 🛠️ Admin Route - Neue Einladungscodes erstellen
app.post('/api/admin/create-invite', authenticate, async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ error: 'Code erforderlich' });
    }
    
    try {
        await pool.query(
            'INSERT INTO invites (code) VALUES ($1)',
            [code]
        );
        
        console.log(`✅ Neuer Einladungscode erstellt: ${code}`);
        res.json({ message: 'Einladungscode erstellt', code });
    } catch (error) {
        if (error.code === '23505') { // Unique constraint violation
            return res.status(400).json({ error: 'Code bereits vorhanden' });
        }
        console.error('Create invite error:', error);
        res.status(500).json({ error: 'Datenbankfehler' });
    }
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
async function startServer() {
    try {
        // Datenbank initialisieren
        await initDatabase();
        
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log('🧠 NeoOS Backend Server mit PostgreSQL gestartet!');
            console.log(`📡 Port: ${PORT}`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🐘 Datenbank: PostgreSQL`);
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
        process.on('SIGINT', async () => {
            console.log('\n🛑 Server wird beendet...');
            
            await pool.end();
            console.log('🐘 PostgreSQL Pool geschlossen');
            
            server.close(() => {
                console.log('🚪 Server beendet');
                process.exit(0);
            });
        });

        process.on('SIGTERM', async () => {
            console.log('🛑 SIGTERM empfangen, beende Server...');
            
            await pool.end();
            server.close(() => {
                process.exit(0);
            });
        });
        
    } catch (error) {
        console.error('❌ Fehler beim Server-Start:', error);
        process.exit(1);
    }
}

startServer();
