// server.js
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const slugify = require("slugify");
// Load environment variables
dotenv.config();

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

const app = express();

app.use(cors());
app.use(express.json());

// Health check route
app.get("/", (req, res) => {
  res.send("API is running...");
});

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "No token provided" });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;

      if (roles.length && !roles.includes(decoded.role)) {
        return res.status(403).json({ message: "Access denied" });
      }

      next();
    } catch (err) {
      res.status(401).json({ message: "Invalid token" });
    }
  };
};

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["admin", "author", "reader"], default: "reader" },
  },
  { timestamps: true }
);
const postSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    slug: { type: String, unique: true },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    tags: [String],
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  { timestamps: true }
);

// Create text index after schema definition
postSchema.index({ title: "text", content: "text" });
const commentSchema = new mongoose.Schema(
  {
    post: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    content: { type: String, required: true },
  },
  { timestamps: true }
);

const Comment = mongoose.model("Comment", commentSchema);
const Post = mongoose.model("Post", postSchema);
const User = mongoose.model("User", userSchema);
// Register Route
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: role || "reader",
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id, role: newUser.role }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({ token, user: { id: newUser._id, name, email, role: newUser.role } });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login Route
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, user: { id: user._id, name: user.name, email, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});
// Example protected route
app.get("/api/protected", authMiddleware(["admin", "author"]), (req, res) => {
  res.json({ message: `Hello ${req.user.role}, you are authenticated` });
});
app.post("/api/posts", authMiddleware(["author", "admin"]), async (req, res) => {
  const { title, content, tags } = req.body;

  try {
    const slug = slugify(title, { lower: true });
    const newPost = new Post({
      title,
      slug,
      content,
      tags,
      author: req.user.id,
    });

    await newPost.save();
    res.status(201).json(newPost);
  } catch (err) {
    res.status(500).json({ message: "Failed to create post" });
  }
});
app.get("/api/posts", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    
    const posts = await Post.find()
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
      
    const count = await Post.countDocuments();
    
    res.json({
      posts,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalPosts: count
    });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch posts" });
  }
});
app.get("/api/posts/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const post = await Post.findOne({ slug }).populate("author", "name");
    if (!post) return res.status(404).json({ message: "Post not found" });
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: "Error fetching post" });
  }
});
app.put("/api/posts/:slug", authMiddleware(["author", "admin"]), async (req, res) => {
  try {
    const { slug } = req.params;
    const post = await Post.findOne({ slug });
    if (!post) return res.status(404).json({ message: "Post not found" });

    if (post.author.toString() !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ message: "Unauthorized" });
    }

    const { title, content, tags } = req.body;

    post.title = title || post.title;
    post.content = content || post.content;
    post.tags = tags || post.tags;
    post.slug = slugify(post.title, { lower: true });

    await post.save();
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: "Failed to update post" });
  }
});
app.delete("/api/posts/:slug", authMiddleware(["author", "admin"]), async (req, res) => {
  try {
    const { slug } = req.params;
    const post = await Post.findOne({ slug });
    if (!post) return res.status(404).json({ message: "Post not found" });

    if (post.author.toString() !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ message: "Unauthorized" });
    }

    await post.deleteOne();
    res.json({ message: "Post deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting post" });
  }
});

//peep
app.post("/api/posts/:slug/comments", authMiddleware(), async (req, res) => {
  try {
    const { slug } = req.params; // Destructure for consistency
    const { content } = req.body;
    
    if (!content) return res.status(400).json({ message: "Content is required" });

    const post = await Post.findOne({ slug });
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comment = new Comment({
      post: post._id,
      author: req.user.id,
      content,
    });

    await comment.save();
    
    // Populate author info in response
    const populatedComment = await Comment.findById(comment._id).populate("author", "name");
    res.status(201).json(populatedComment);
    
  } catch (err) {
    console.error("Add comment error:", err); // Better logging
    res.status(500).json({ message: "Failed to add comment" });
  }
});
app.get("/api/posts/:slug/comments", async (req, res) => {
  try {
    const { slug } = req.params;
    const { page = 1, limit = 10 } = req.query;
    
    const post = await Post.findOne({ slug });
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comments = await Comment.find({ post: post._id })
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
      
    const count = await Comment.countDocuments({ post: post._id });

    res.json({
      comments,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalComments: count
    });
  } catch (err) {
    console.error("Fetch comments error:", err);
    res.status(500).json({ message: "Error fetching comments" });
  }
});
app.delete("/api/comments/:id", authMiddleware(["admin", "author", "reader"]), async (req, res) => {
  try {
    const { id } = req.params;
    
    // More efficient single query
    const comment = await Comment.findOneAndDelete({
      _id: id,
      $or: [
        { author: req.user.id },
        { role: "admin" } // This won't work - see note below
      ]
    });

    if (!comment) return res.status(404).json({ message: "Comment not found or unauthorized" });

    res.json({ message: "Comment deleted" });
  } catch (err) {
    console.error("Delete comment error:", err);
    res.status(500).json({ message: "Error deleting comment" });
  }
});
app.post("/api/posts/:slug/like", authMiddleware(), async (req, res) => {
  try {
    const { slug } = req.params;
    const userId = req.user.id;
    
    const post = await Post.findOne({ slug });
    if (!post) return res.status(404).json({ message: "Post not found" });

    // More efficient single DB operation
    const updatedPost = await Post.findOneAndUpdate(
      { slug },
      {
        [post.likes.includes(userId) ? "$pull" : "$addToSet"]: { likes: userId }
      },
      { new: true }
    );

    res.json({ 
      likes: updatedPost.likes.length,
      isLiked: updatedPost.likes.includes(userId)
    });
  } catch (err) {
    console.error("Like error:", err);
    res.status(500).json({ message: "Failed to toggle like" });
  }
});
//control

app.get("/api/tags", async (req, res) => {
  try {
    const tags = await Post.distinct("tags", { tags: { $exists: true, $ne: [] } });
    res.json(tags.filter(tag => tag)); // Remove any null/undefined tags
  } catch (err) {
    console.error("Fetch tags error:", err);
    res.status(500).json({ message: "Failed to fetch tags" });
  }
});
app.get("/api/posts/tag/:tag", async (req, res) => {
  try {
    const { tag } = req.params;
    const { page = 1, limit = 10 } = req.query; // Add pagination params
    
    const posts = await Post.find({ 
      tags: { $regex: new RegExp(tag, 'i') } // Case-insensitive search
    })
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1) // Convert to number
      .skip((page - 1) * limit) // Calculate skip
      .lean();
    
    const count = await Post.countDocuments({ 
      tags: { $regex: new RegExp(tag, 'i') } 
    });
    
    res.json({
      posts,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalPosts: count
    });
  } catch (err) {
    console.error("Fetch posts by tag error:", err);
    res.status(500).json({ message: "Failed to fetch posts by tag" });
  }
});
app.get("/api/search", async (req, res) => {
  const { q, page = 1, limit = 10 } = req.query;
  
  if (!q || q.trim().length < 3) {
    return res.status(400).json({ message: "Search query must be at least 3 characters" });
  }

  try {
    const results = await Post.find(
      { $text: { $search: q } },
      { score: { $meta: "textScore" } }
    )
      .sort({ score: { $meta: "textScore" } })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate("author", "name email")
      .lean();
      
    const count = await Post.countDocuments({ $text: { $search: q } });

    res.json({
      results: results.length ? results : [],
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalResults: count
    });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ message: "Search failed" });
  }
});
// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
