const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// This is the correct way to add a route for the root URL
app.get("/", (req, res) => {
    res.send("Hello from the Jovial Flames backend!");
});

// ... your other routes (e.g., app.get("/api/products", ...))

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}); 
// Import required packages
const express = require('express');
const cors = require('cors');

// Create an Express application
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies and enable CORS
app.use(express.json());
app.use(cors());

// In-memory "database" to store blog posts
let posts = [
  { id: 1, title: 'Welcome to My Blog', content: 'This is the first post.' },
  { id: 2, title: 'Node.js and Express', content: 'Building APIs is fun and easy with Express.' },
];
let nextId = 3; // To simulate auto-incrementing IDs

// --- API Endpoints ---

// 1. GET /posts - Fetch all blog posts
app.get('/posts', (req, res) => {
  res.json(posts);
});

// 2. GET /posts/:id - Fetch a single post by its ID
app.get('/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id);
  const post = posts.find(p => p.id === postId);
  if (post) {
    res.json(post);
  } else {
    res.status(404).send('Post not found');
  }
});

// 3. POST /posts - Create a new post
app.post('/posts', (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).send('Title and content are required.');
  }
  const newPost = { id: nextId++, title, content };
  posts.push(newPost);
  res.status(201).json(newPost);
});

// 4. PUT /posts/:id - Update an existing post
app.put('/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id);
  const postIndex = posts.findIndex(p => p.id === postId);
  if (postIndex !== -1) {
    const { title, content } = req.body;
    posts[postIndex] = { ...posts[postIndex], title: title || posts[postIndex].title, content: content || posts[postIndex].content };
    res.json(posts[postIndex]);
  } else {
    res.status(404).send('Post not found');
  }
});

// 5. DELETE /posts/:id - Delete a post
app.delete('/posts/:id', (req, res) => {
  const postId = parseInt(req.params.id);
  const initialLength = posts.length;
  posts = posts.filter(p => p.id !== postId);
  if (posts.length < initialLength) {
    res.status(204).send(); // No content to send back
  } else {
    res.status(404).send('Post not found');
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});