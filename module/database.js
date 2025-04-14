const mongoose = require("mongoose");

const conversationSchema = new mongoose.Schema({
    question: String,
    answer: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const adminSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: {
        type: String,
        default: "admin"
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    conversations: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Conversation'
    }]
});
const AdminModel = mongoose.model("Admin", adminSchema);
const ConversationModel = mongoose.model("Conversation", conversationSchema);

module.exports = { AdminModel, ConversationModel };
