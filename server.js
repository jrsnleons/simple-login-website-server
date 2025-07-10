require("dotenv").config(); // Load environment variables first

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const path = require("path");
const crypto = require("crypto");

const app = express();

// CORS configuration
const corsOptions = {
    origin: [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8080",
        "http://localhost:5173", // Vite default
        "http://127.0.0.1:5500", // Live Server
        "http://127.0.0.1:3000",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
};

// Middleware
app.use(cors(corsOptions)); // Enable CORS
app.use(express.json()); // Parse JSON bodies

const generateSecureSecret = () => {
    return crypto.randomBytes(64).toString("hex");
};

// Environment variables with defaults
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 10;
const DATA_FILE_PATH = process.env.DATA_FILE_PATH || "users.json";
const JWT_SECRET = process.env.JWT_SECRET || generateSecureSecret();

// Warn if using fallback secret
if (!process.env.JWT_SECRET) {
    if (NODE_ENV === "production") {
        console.error(
            "⚠️  WARNING: JWT_SECRET not set in production! Using generated secret."
        );
        console.error(
            "⚠️  This means tokens will be invalid after server restart!"
        );
    } else {
        console.log("ℹ️  Using generated JWT secret for development");
    }
}

// File storage setup
const DATA_FILE = path.join(__dirname, DATA_FILE_PATH);
let users = [];

// Load users from JSON file on startup
async function loadUsers() {
    try {
        const data = await fs.readFile(DATA_FILE, "utf8");
        users = JSON.parse(data).users || [];
        console.log(`Loaded ${users.length} users from JSON file`);
    } catch (error) {
        if (error.code === "ENOENT") {
            console.log("No existing users file found, starting fresh");
            users = [];
        } else {
            console.error("Error loading users:", error);
            users = [];
        }
    }
}

// Save users to JSON file
async function saveUsers() {
    try {
        const data = JSON.stringify({ users }, null, 2);
        await fs.writeFile(DATA_FILE, data, "utf8");
        console.log(`Saved ${users.length} users to JSON file`);
    } catch (error) {
        console.error("Error saving users:", error);
    }
}

// Initialize users on startup
loadUsers();

app.post("/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Check if user already exists
        const existingUser = users.find((u) => u.email === email);
        if (existingUser) {
            return res
                .status(409)
                .json({ message: "Email already registered" });
        }

        // Hash password with env variable
        const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // Add user to storage
        const newUser = {
            id: users.length + 1,
            username,
            email,
            password: hashedPassword,
            createdAt: new Date(),
        };
        users.push(newUser);

        // Save to JSON file
        await saveUsers();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res
                .status(400)
                .json({ error: "Email and password are required" });
        }

        // Find user by email
        const user = users.find((u) => u.email === email);
        if (!user) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Verify password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                username: user.username,
            },
            JWT_SECRET,
            { expiresIn: "24h" }
        );

        // Return success with token
        res.status(200).json({
            message: "Login successful",
            token: token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
            },
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Get all users (protected route)
app.get("/users", authenticateToken, (req, res) => {
    const usersWithoutPasswords = users.map(({ password, ...user }) => user);
    res.json(usersWithoutPasswords);
});

// Get current user profile (protected route)
app.get("/profile", authenticateToken, (req, res) => {
    const user = users.find((u) => u.id === req.user.userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// Basic route to test server
app.get("/", (req, res) => {
    res.json({
        message: "Server is running!",
        storage: "JSON file",
        userCount: users.length,
        environment: NODE_ENV,
    });
});

// JWT verification middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: "Access token required" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Invalid or expired token" });
        }
        req.user = user;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} in ${NODE_ENV} mode`);
});
