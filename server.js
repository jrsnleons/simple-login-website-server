const express = require("express");
const bcrypt = require("bcrypt");
const fs = require("fs").promises;
const path = require("path");

const app = express();

// Middleware
app.use(express.json()); // Parse JSON bodies

// File storage setup
const DATA_FILE = path.join(__dirname, "users.json");
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

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

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

app.get("/users", (req, res) => {
    const usersWithoutPasswords = users.map(({ password, ...user }) => user);
    res.json(usersWithoutPasswords);
});

// Basic route to test server
app.get("/", (req, res) => {
    res.json({
        message: "Server is running!",
        storage: "JSON file",
        userCount: users.length,
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
