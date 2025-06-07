const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dns = require('dns');

// Load environment variables
dotenv.config();

// Configure DNS to use Google's servers
dns.setServers(['8.8.8.8', '8.8.4.4']);

// Debug environment variables
console.log("Environment check:");
console.log("PORT:", process.env.PORT);
console.log("MONGO_URI exists:", !!process.env.MONGO_URI);
console.log("MONGO_URI first 20 chars:", process.env.MONGO_URI ? process.env.MONGO_URI.substring(0, 20) + "..." : "not set");
console.log("JWT_SECRET exists:", !!process.env.JWT_SECRET);

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection with improved settings
console.log("Setting up MongoDB connection...");

let isConnected = false;

const connectWithRetry = async () => {
    try {
        const mongoUri = process.env.MONGO_URI;
        console.log("Attempting to connect to MongoDB...");

        const options = {
            serverSelectionTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            connectTimeoutMS: 30000,
            family: 4,
            maxPoolSize: 10,
            minPoolSize: 5,
            retryWrites: true,
            w: 'majority'
        };

        // Connect to MongoDB
        await mongoose.connect(mongoUri, options);
        console.log("✅ Connected to MongoDB successfully");
        isConnected = true;

        // Wait for the connection to be ready
        if (mongoose.connection.readyState === 1) {
            console.log("Connection is ready");
        } else {
            console.log("Connection not fully established yet");
        }
        
    } catch (err) {
        console.error("❌ MongoDB connection error details:");
        console.error("Error name:", err.name);
        console.error("Error message:", err.message);
        console.error("Error code:", err.code);
        isConnected = false;
        
        if (err.name === 'MongoServerSelectionError') {
            console.error("Server selection error - possible causes:");
            console.error("1. MongoDB server is not running");
            console.error("2. Network connectivity issues");
            console.error("3. IP address not whitelisted in MongoDB Atlas");
            console.error("4. Invalid connection string");
        }
        
        console.log("Retrying connection in 5 seconds...");
        setTimeout(connectWithRetry, 5000);
    }
};

// Start the connection process
connectWithRetry();

// Connection event listeners with more detailed state logging
mongoose.connection.on('connected', () => {
    console.log('Mongoose connected to MongoDB');
    console.log('Connection state:', mongoose.connection.readyState);
    isConnected = true;
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose connection error:', err);
    console.error('Connection state:', mongoose.connection.readyState);
    isConnected = false;
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose disconnected from MongoDB');
    console.log('Connection state:', mongoose.connection.readyState);
    isConnected = false;
    console.log("Attempting to reconnect...");
    connectWithRetry();
});

// Middleware to check database connection with more detailed state
const checkDatabaseConnection = (req, res, next) => {
    if (!isConnected || mongoose.connection.readyState !== 1) {
        return res.status(503).json({ 
            message: "Database connection not ready. Please try again in a few seconds.",
            error: "Database connection not established",
            state: mongoose.connection.readyState
        });
    }
    next();
};

// Debug middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
});

// ✅ User schema & model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "member" },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});
const User = mongoose.model("User", userSchema);

// ✅ Register route
app.post("/register", checkDatabaseConnection, async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser)
            return res.status(400).json({ message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

        res.status(201).json({
            message: "User registered successfully",
            token,
            user: { id: newUser._id, name: newUser.name, email: newUser.email }
        });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ message: "Error registering user", error: err.message });
    }
});

// ✅ Login route
app.post("/login", checkDatabaseConnection, async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user)
            return res.status(404).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

        res.status(200).json({
            message: "Login successful",
            token,
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Login failed", error: err.message });
    }
});

// Enhanced Profile route
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Get additional user information
        const userProfile = {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role || "member",
            createdAt: user.createdAt,
            lastLogin: user.lastLogin || new Date(),
            // Add any other user information you want to display
        };

        res.json({
            message: "Profile retrieved successfully",
            profile: userProfile
        });
    } catch (err) {
        console.error("Profile error:", err);
        res.status(500).json({ message: "Error retrieving profile" });
    }
});

// Update Profile route
app.put("/profile", verifyToken, async (req, res) => {
    try {
        const { name, email } = req.body;
        const user = await User.findById(req.userId);
        
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Update user information
        if (name) user.name = name;
        if (email) user.email = email;

        await user.save();

        res.json({
            message: "Profile updated successfully",
            profile: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role || "member",
                updatedAt: new Date()
            }
        });
    } catch (err) {
        console.error("Profile update error:", err);
        res.status(500).json({ message: "Error updating profile" });
    }
});

// ✅ Middleware to verify JWT
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Access Denied" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        res.status(400).json({ message: "Invalid Token" });
    }
}

// ✅ Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
