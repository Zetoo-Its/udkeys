import express from "express";
import { Client, GatewayIntentBits, Events, EmbedBuilder } from "discord.js";
import crypto from "crypto";
import fs from "fs";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import os from "os";

dotenv.config();

const app = express();
app.use(express.json());

const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const PORT = process.env.PORT || 3000;
const DEBUG_USER_ID = process.env.DEBUG_USER_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const REDACT_LOGS = process.env.REDACT_LOGS === "true";

const KEY_FILE = "./keys.json";
const BLOCK_FILE = "./blocks.json";

// --------------------
// Key Storage
// --------------------
let keyStore = new Map();
if (fs.existsSync(KEY_FILE)) {
    const data = JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
    keyStore = new Map(
        Object.entries(data).map(([key, value]) => [
            key,
            { userId: value.userId, expiresAt: value.expiresAt },
        ])
    );
}
function saveKeys() {
    const obj = Object.fromEntries(keyStore);
    fs.writeFileSync(KEY_FILE, JSON.stringify(obj, null, 2));
}

// --------------------
// Block Storage
// --------------------
let blockStore = new Set();
if (fs.existsSync(BLOCK_FILE)) {
    const data = JSON.parse(fs.readFileSync(BLOCK_FILE, "utf8"));
    blockStore = new Set(data);
}
function saveBlocks() {
    fs.writeFileSync(BLOCK_FILE, JSON.stringify([...blockStore], null, 2));
}

// --------------------
// Helper Functions
// --------------------
function generateKey() {
    return crypto.randomBytes(8).toString("hex");
}
function parseTime(timeStr) {
    const match = timeStr.match(/^(\d+)([smhd])$/);
    if (!match) return null;
    const [, amount, unit] = match;
    const multipliers = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    return parseInt(amount) * multipliers[unit];
}

// --------------------
// Discord Client
// --------------------
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
    ],
});

client.once(Events.ClientReady, () => {
    console.log(`Bot ready as ${client.user.tag}`);
    const now = Date.now();
    for (const [key, data] of keyStore.entries()) {
        if (now > data.expiresAt) keyStore.delete(key);
    }
    saveKeys();
});

// ---------------------------
// Logging Function
// ---------------------------
async function logValidation(key, hwid, userAgent, origin, referer, acceptLang, host, protocol, url, method, headers, success) {
    if (!LOG_CHANNEL_ID) return;
    const channel = await client.channels.fetch(LOG_CHANNEL_ID);
    if (!channel?.isTextBased()) return;

    const placeholder = "REDACTED";

    const embed = new EmbedBuilder()
        .setTitle("🔍 Key Validation")
        .setColor(success ? "#00FF00" : "#FF0000")
        .addFields(
            { name: "Key", value: REDACT_LOGS ? placeholder : key },
            { name: "HWID", value: REDACT_LOGS ? placeholder : hwid },
            { name: "User-Agent", value: REDACT_LOGS ? placeholder : userAgent },
            { name: "Origin", value: REDACT_LOGS ? placeholder : origin },
            { name: "Referer", value: REDACT_LOGS ? placeholder : referer },
            { name: "Accept-Language", value: REDACT_LOGS ? placeholder : acceptLang },
            { name: "Host", value: REDACT_LOGS ? placeholder : host },
            { name: "Protocol", value: REDACT_LOGS ? placeholder : protocol },
            { name: "Request URL", value: REDACT_LOGS ? placeholder : url },
            { name: "Method", value: REDACT_LOGS ? placeholder : method },
            { name: "Headers", value: REDACT_LOGS ? placeholder : `\`\`\`json\n${headers}\n\`\`\`` },
            { name: "Result", value: success ? "✅ Valid" : "❌ Invalid / Expired / Blocked" },
            { name: "Time", value: new Date().toUTCString() }
        )
        .setTimestamp();

    channel.send({ embeds: [embed] });
}

// ---------------------------
// Rate Limiter
// ---------------------------
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "Too many requests, try again later." },
});

app.use("/validate", limiter);

// ---------------------------
// Discord Commands
// ---------------------------
client.on(Events.MessageCreate, async (message) => {
    if (!message.content.startsWith("!")) return;
    const args = message.content.trim().split(/\s+/);
    const command = args[0];

    const memberRoles = message.member?.roles.cache;
    const hasAdminRole = memberRoles?.has(ADMIN_ROLE_ID);
    const isAdminOrDebug = hasAdminRole || message.author.id === DEBUG_USER_ID;

    // ---------- !gen-key ----------
    if (command === "!gen-key") {
        if (!isAdminOrDebug) return message.reply("❌ No permission.");
        const userId = args[1];
        const timeStr = args[2];
        const ms = parseTime(timeStr);
        if (!userId || !ms) return message.reply("Usage: !gen-key {user-id} {time}");
        const key = generateKey();
        const expiresAt = Date.now() + ms;
        keyStore.set(key, { userId, expiresAt });
        saveKeys();
        setTimeout(() => { keyStore.delete(key); saveKeys(); }, ms);

        try {
            const user = await client.users.fetch(userId);
            await user.send({
                embeds: [new EmbedBuilder()
                    .setTitle("🔑 You received a key!")
                    .setColor("#00FF00")
                    .addFields({ name: "Key", value: `\`${key}\`` }, { name: "Valid For", value: timeStr })
                    .setTimestamp()]
            });
            message.reply(`✅ Key sent to <@${userId}> via DM.`);
        } catch { message.reply("❌ Could not send DM."); }
    }

    // ---------- !keys ----------
    if (command === "!keys") {
        const userKeys = Array.from(keyStore.entries())
            .filter(([_, v]) => v.userId === message.author.id)
            .map(([key]) => key);
        try {
            await message.author.send({
                embeds: [new EmbedBuilder()
                    .setTitle("📋 Your Active Keys")
                    .setColor("#FFA500")
                    .setDescription(userKeys.length ? userKeys.map(k => `\`${k}\``).join("\n") : "You have no active keys.")
                    .setTimestamp()]
            });
            message.reply("✅ Your keys have been sent to your DMs.");
        } catch { message.reply("❌ Could not send DM."); }
    }

    // ---------- !del-key ----------
    if (command === "!del-key") {
        if (!isAdminOrDebug) return message.reply("❌ No permission.");
        const key = args[1];
        if (!key || !keyStore.has(key)) return message.reply("❌ Invalid key.");
        keyStore.delete(key); saveKeys();
        await message.author.send({
            embeds: [new EmbedBuilder()
                .setTitle("🗑️ Key Deleted")
                .setColor("#FF0000")
                .setDescription(`\`${key}\` deleted.`)
                .setTimestamp()]
        });
        message.reply("✅ Key deletion info sent to your DMs.");
    }

    // ---------- !get-keys ----------
    if (command === "!get-keys") {
        if (!isAdminOrDebug) return message.reply("❌ No permission.");
        const userId = args[1];
        if (!userId) return message.reply("Usage: !get-keys {user-id}");

        const userKeys = Array.from(keyStore.entries())
            .filter(([_, v]) => v.userId === userId)
            .map(([key]) => key);

        if (!userKeys.length) return message.reply("❌ No active keys for this user.");

        try {
            await message.author.send({
                embeds: [new EmbedBuilder()
                    .setTitle(`📋 Keys of user ${userId}`)
                    .setColor("#FFA500")
                    .setDescription(userKeys.map(k => `\`${k}\``).join("\n"))
                    .setTimestamp()]
            });
            message.reply(`✅ Keys of user ${userId} sent to your DMs.`);
        } catch { message.reply("❌ Could not send DM to you. Check privacy settings."); }
    }

    // ---------- !block ----------
    if (command === "!block") {
        if (!isAdminOrDebug) return message.reply("❌ No permission.");
        const target = args[1]; if (!target) return message.reply("Usage: !block {hwid}");
        blockStore.add(target); saveBlocks();
        message.reply(`✅ \`${target}\` has been blocked.`);
    }

    // ---------- !unblock ----------
    if (command === "!unblock") {
        if (!isAdminOrDebug) return message.reply("❌ No permission.");
        const target = args[1]; if (!target) return message.reply("Usage: !unblock {hwid}");
        blockStore.delete(target); saveBlocks();
        message.reply(`✅ \`${target}\` has been unblocked.`);
    }

    // ---------- !help ----------
    if (command === "!help") {
        const embed = new EmbedBuilder()
            .setTitle("📖 Key System Commands")
            .setColor("#00BFFF")
            .setDescription(
                "**!gen-key {user-id} {time}** - Generate key (Admin/Debug)\n" +
                "**!keys** - Show your keys via DM\n" +
                "**!del-key {key}** - Delete key (Admin/Debug)\n" +
                "**!get-keys {user-id}** - Send keys of user to your DM (Admin/Debug)\n" +
                "**!block {hwid}** - Block HWID (Admin/Debug)\n" +
                "**!unblock {hwid}** - Unblock HWID (Admin/Debug)\n" +
                "**!help** - Show this help"
            )
            .setTimestamp();
        message.reply({ embeds: [embed] });
    }
});

// ---------------------------
// Webserver Validate Endpoint
// ---------------------------
app.post("/validate", async (req, res) => {
    const { key, hwid } = req.body;
    const userAgent = req.headers['user-agent'] || "Unknown";
    const origin = req.headers['origin'] || "Unknown";
    const referer = req.headers['referer'] || "Unknown";
    const acceptLang = req.headers['accept-language'] || "Unknown";
    const host = req.headers['host'] || "Unknown";
    const protocol = req.protocol;
    const url = req.originalUrl;
    const method = req.method;
    const allHeaders = JSON.stringify(req.headers, null, 2);

    if (!key || !hwid) return res.status(400).json({ success: false, message: "Key and HWID required" });
    if (blockStore.has(hwid)) return res.status(403).json({ success: false, message: "Blocked HWID" });

    let success = false;

    if (!keyStore.has(key)) {
        success = false;
        res.status(401).json({ success: false, message: "Invalid key" });
    } else {
        const data = keyStore.get(key);
        if (Date.now() > data.expiresAt) {
            keyStore.delete(key); saveKeys();
            success = false;
            res.status(401).json({ success: false, message: "Key expired" });
        } else {
            success = true;
            res.status(200).json({ success: true, message: "Key valid" });
        }
    }

    await logValidation(key, hwid, userAgent, origin, referer, acceptLang, host, protocol, url, method, allHeaders, success);
});

// ---------------------------
// Start Server
// ---------------------------
app.listen(PORT, () => {
    console.log(`Webserver running on port ${PORT}`);

    // Alle IPv4-Adressen anzeigen
    const nets = os.networkInterfaces();
    const results = [];
    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === "IPv4" && !net.internal) {
                results.push(net.address);
            }
        }
    }
    console.log("Accessible IPs:", results.join(", ") || "None");
});

client.login(DISCORD_TOKEN);
