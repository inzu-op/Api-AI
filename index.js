require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { AdminModel, ConversationModel } = require('./module/database');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const cors = require('cors');

const app = express();
const port = 3000;

// Middleware setup
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ['https://ai-assistant-lyart-delta.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
    exposedHeaders: ['*', 'Authorization'],
  })
);

axios.defaults.withCredentials = true;

// Environment variables and database connection
const jwtSecretKey = process.env.JWT_SECRET_KEY;
const mongoDBUri = process.env.MONGODB_URI;
console.log('MongoDB URI:', mongoDBUri);

mongoose
  .connect(mongoDBUri)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Middleware to verify user token
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(404).json({ error: 'No token available' });
  }
  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

// Authentication routes
app.post('/signup', (req, res) => {
  const { name, email, password } = req.body;
  bcrypt
    .hash(password, 10)
    .then((hash) => {
      AdminModel.create({ name, email, password: hash })
        .then((users) => res.json('success'))
        .catch((err) => res.json(err));
    })
    .catch((err) => res.json(err));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  try {
    AdminModel.findOne({ email: email })
      .then((user) => {
        if (user) {
          bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
              const token = jwt.sign(
                { email: user.email, role: user.role },
                process.env.JWT_SECRET_KEY,
                { expiresIn: '1d' }
              );
              res.cookie('token', token, { httpOnly: true, secure: false });
              res.json({ Status: 'success', role: user.role });
            } else {
              res.status(401).json('incorrect password');
            }
          });
        } else {
          res.status(404).json('no user found');
        }
      })
      .catch((err) => res.status(500).json(err));
  } catch (err) {
    res.status(500).json(err);
  }
});

app.get('/verify-token', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: 'No token available' });
  }

  jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    return res
      .status(200)
      .json({ message: 'Token valid', role: decoded.role, email: decoded.email });
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  return res.json({ Status: 'success' });
});

// User data routes
app.get('/userdata/email/:email', async (req, res) => {
  try {
    const email = req.params.email;
    const user = await AdminModel.findOne({ email }).select('_id name email');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('User data fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user data',
    });
  }
});

app.get('/userdata/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    const user = await AdminModel.findById(userId).select('name email');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      success: true,
      user: {
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('User data fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user data',
    });
  }
});

// Chatbot routes and functions
app.post('/chatbot', verifyUser, async (req, res) => {
  try {
    const { inputText } = req.body;
    if (!inputText || inputText.trim() === '') {
      return res.status(400).json({ error: 'Input text cannot be empty' });
    }

    const token = req.cookies.token;
    const decoded = jwt.verify(token, jwtSecretKey);
    const adminEmail = decoded.email;

    const admin = await AdminModel.findOne({ email: adminEmail }).populate(
      'conversations'
    );

    const MAX_HISTORY_SIZE = 10;

    const conversationHistory = admin.conversations
      .slice(-MAX_HISTORY_SIZE)
      .map((conv) => ({
        question: conv.question,
        answer: conv.answer,
      }));
    const domainType = categorizeQuery(inputText);
    const responseLength = estimateResponseLength(inputText);

    const aiInput =
      conversationHistory
        .map((conv) => `User: ${conv.question}\nAI: ${conv.answer}`)
        .join('\n') + `\nUser: ${inputText}\nAI:`;

    const apiKey = process.env.API_KEY;
    const apiUrl = process.env.API_URL;

    const promptWithFormatting =
      aiInput +
      '\n\nYou are a professional AI Assistant specialized in health and career guidance. Your responses should be accurate, elegant, and helpful.' +
      `\n\nRespond with ${responseLength} formatting, focusing on ${domainType} domain.` +
      '\n\n# Core Response Structure' +
      '\n- Keep responses concise and directly answer the question' +
      '\n- For simple questions, provide 1-3 sentence answers' +
      '\n- For complex questions, organize with clear headings' +
      '\n- Use bullet points for lists rather than numbered items when possible' +
      '\n- Include 1-2 high-quality examples instead of many mediocre ones' +
      (domainType === 'health'
        ? '\n\n# Health Response Elements' +
          '\n- Include brief medical disclaimer when appropriate' +
          '\n- Cite trusted sources (WHO, Mayo Clinic, etc.)' +
          '\n- Focus on evidence-based approaches' +
          '\n- Encourage professional consultation when needed'
        : '\n\n# Career Response Elements' +
          '\n- Target advice to experience level (entry/mid/senior)' +
          '\n- For projects, specify difficulty level' +
          '\n- Include actionable next steps' +
          '\n- Provide specific skill development strategies');

    const geminiResponse = await axios({
      url: `${apiUrl}?key=${apiKey}`,
      method: 'post',
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        contents: [
          {
            role: 'user',
            parts: [{ text: promptWithFormatting }],
          },
        ],
        generationConfig: {
          temperature: 0.6,
          topK: 40,
          topP: 0.92,
          maxOutputTokens: responseLength === 'brief' ? 300 : 800,
        },
      },
    });
    let responseText = geminiResponse.data.candidates[0].content.parts[0].text;
    responseText = formatResponse(responseText, domainType, responseLength);

    const conversation = {
      question: inputText,
      answer: responseText,
      timestamp: new Date(),
    };

    const savedConversation = await ConversationModel.create(conversation);

    await AdminModel.findOneAndUpdate(
      { email: adminEmail },
      { $push: { conversations: savedConversation._id } }
    );

    res.json({
      candidates: [
        {
          content: {
            parts: [{ text: responseText }],
          },
        },
      ],
      savedToDB: true,
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(error.response?.status || 500).json({
      error: error.response?.data?.error?.message || error.message || 'Unknown error',
    });
  }
});

function categorizeQuery(query) {
  const healthKeywords = [
    'health',
    'fitness',
    'diet',
    'exercise',
    'nutrition',
    'medical',
    'mental health',
    'anxiety',
    'depression',
    'sleep',
    'doctor',
  ];

  const careerKeywords = [
    'career',
    'job',
    'resume',
    'interview',
    'work',
    'profession',
    'skill',
    'project',
    'programming',
    'coding',
    'development',
  ];

  const lowerQuery = query.toLowerCase();

  let healthScore = healthKeywords.filter((keyword) => lowerQuery.includes(keyword)).length;
  let careerScore = careerKeywords.filter((keyword) => lowerQuery.includes(keyword)).length;

  return healthScore > careerScore ? 'health' : 'career';
}

function estimateResponseLength(query) {
  const words = query.split(/\s+/).length;

  if (words < 10) return 'brief';
  if (words < 25) return 'moderate';
  return 'detailed';
}

function formatResponse(text, domain, length) {
  text = text.replace(/\n{3,}/g, '\n\n');

  if (domain === 'health' && length !== 'brief') {
    text = text.replace(/^# (.*Health.*)$/im, '# $1 💪');
    text = text.replace(/^# (.*Nutrition.*)$/im, '# $1 🥗');
    text = text.replace(/^# (.*Exercise.*)$/im, '# $1 🏃‍♂️');
    text = text.replace(/^# (.*Mental.*)$/im, '# $1 🧠');
  } else if (domain === 'career' && length !== 'brief') {
    text = text.replace(/^# (.*Career.*)$/im, '# $1 💼');
    text = text.replace(/^# (.*Skills.*)$/im, '# $1 🔧');
    text = text.replace(/^# (.*Interview.*)$/im, '# $1 🗣️');
    text = text.replace(/^# (.*Project.*)$/im, '# $1 🚀');
  }

  if (length === 'brief') {
    text = text.replace(/[\*\_\#\`]/g, '');
  }

  return text;
}

// Conversation management routes
app.get('/conversations', verifyUser, async (req, res) => {
  try {
    const token = req.cookies.token;
    const decoded = jwt.verify(token, jwtSecretKey);
    const admin = await AdminModel.findOne({ email: decoded.email }).populate(
      'conversations'
    );
    res.json(admin.conversations);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching conversations' });
  }
});

app.delete('/conversation/:id', verifyUser, async (req, res) => {
  try {
    const { id } = req.params;

    const conversation = await ConversationModel.findById(id);
    if (!conversation) {
      return res.status(404).json({ message: 'Conversation not found' });
    }

    await ConversationModel.findByIdAndDelete(id);

    await AdminModel.updateOne(
      { email: req.user.email },
      { $pull: { conversations: id } }
    );

    res.status(200).json({ message: 'Conversation deleted successfully' });
  } catch (error) {
    console.error('Error in delete conversation:', error);
    res.status(500).json({ message: 'Failed to delete conversation' });
  }
});

app.delete('/conversations/all', verifyUser, async (req, res) => {
  try {
    const token = req.cookies.token;
    const decoded = jwt.verify(token, jwtSecretKey);

    const admin = await AdminModel.findOne({ email: decoded.email });
    if (!admin) {
      return res.status(404).json({ message: 'User not found' });
    }

    await ConversationModel.deleteMany({ _id: { $in: admin.conversations } });

    admin.conversations = [];
    await admin.save();

    res.status(200).json({ message: 'All conversations deleted successfully' });
  } catch (error) {
    console.error('Error deleting all conversations:', error);
    res.status(500).json({ message: 'Failed to delete all conversations' });
  }
});

// Test route
app.get('/chat', verifyUser, (req, res) => {
  res.send('hello');
});

// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
