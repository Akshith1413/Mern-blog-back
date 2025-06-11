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
// Add security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.removeHeader('X-Powered-By');
  next();
});
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
    deleted: { type: Boolean, default: false, index: true }, // New field
    deletedAt: { type: Date }
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
    deleted: { type: Boolean, default: false, index: true },
    deletedAt: { type: Date }
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
    
    const posts = await Post.find({ deleted: false })  // Add this filter
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
      
    const count = await Post.countDocuments({ deleted: false });  // Add this filter
    
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
    const post = await Post.findOne({ slug, deleted: false })  // Add this filter
      .populate("author", "name");
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
    
    const post = await Post.findOne({ slug, deleted: false });
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comments = await Comment.find({ 
      post: post._id,
      deleted: false  // Add this filter
    })
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
      
    const count = await Comment.countDocuments({ 
      post: post._id,
      deleted: false  // Add this filter
    });

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
    const comment = await Comment.findOneAndUpdate(
      {
        _id: req.params.id,
        deleted: false,
        $or: [
          { author: req.user.id },
          { role: "admin" }
        ]
      },
      { $set: { deleted: true, deletedAt: new Date() } },
      { new: true }
    );

    if (!comment) {
      return res.status(404).json({ 
        message: "Comment not found, already deleted, or unauthorized"
      });
    }

    res.json({ 
      message: "Comment soft deleted",
      commentId: comment._id,
      deletedAt: comment.deletedAt
    });
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
    const { page = 1, limit = 10 } = req.query;
    
    const posts = await Post.find({ 
      tags: { $regex: new RegExp(tag, 'i') },
      deleted: false  // Add this filter
    })
      .populate("author", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean();
    
    const count = await Post.countDocuments({ 
      tags: { $regex: new RegExp(tag, 'i') },
      deleted: false  // Add this filter
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
    const results = await Post.find({
      $text: { $search: q },
      deleted: false  // Add this filter
    })
      .sort({ score: { $meta: "textScore" } })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate("author", "name email")
      .lean();
      
    const count = await Post.countDocuments({ 
      $text: { $search: q },
      deleted: false  // Add this filter
    });

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
//admin
app.get("/api/admin/stats", authMiddleware(["admin"]), async (req, res) => {
  try {
    const [
      totalUsers,
      authors,
      readers,
      admins,
      totalPosts,
      activePosts,
      deletedPosts,
      totalComments
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: "author" }),
      User.countDocuments({ role: "reader" }),
      User.countDocuments({ role: "admin" }),
      Post.countDocuments(),
      Post.countDocuments({ deleted: false }),
      Post.countDocuments({ deleted: true }),
      Comment.countDocuments()
    ]);

    res.json({
      users: { total: totalUsers, authors, readers, admins },
      posts: { total: totalPosts, active: activePosts, deleted: deletedPosts },
      comments: totalComments,
      lastUpdated: new Date()
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    res.status(500).json({ 
      message: "Failed to fetch dashboard stats",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
// Soft delete post
app.delete("/api/admin/posts/:id", authMiddleware(["admin"]), async (req, res) => {
  try {
    const post = await Post.findOneAndUpdate(
      { _id: req.params.id, deleted: false },
      { $set: { deleted: true, deletedAt: new Date() } },
      { new: true }
    );

    if (!post) {
      return res.status(404).json({ 
        message: "Post not found or already deleted"
      });
    }

    // Soft delete all comments for this post
    await Comment.updateMany(
      { post: post._id },
      { $set: { deleted: true, deletedAt: new Date() } }
    );

    res.json({ 
      message: "Post and its comments soft deleted",
      postId: post._id,
      deletedAt: post.deletedAt,
      commentsDeleted: true
    });
  } catch (err) {
    console.error("Soft delete error:", err);
    res.status(500).json({ 
      message: "Failed to soft delete post",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
// Restore post
app.put("/api/admin/posts/:id/restore", authMiddleware(["admin"]), async (req, res) => {
  try {
    const post = await Post.findOneAndUpdate(
      { _id: req.params.id, deleted: true },
      { $set: { deleted: false }, $unset: { deletedAt: 1 } },
      { new: true }
    );

    if (!post) {
      return res.status(404).json({ 
        message: "Post not found or already active"
      });
    }

    // Restore all comments for this post
    await Comment.updateMany(
      { post: post._id },
      { $set: { deleted: false }, $unset: { deletedAt: 1 } }
    );

    res.json({ 
      message: "Post and its comments restored",
      postId: post._id,
      commentsRestored: true
    });
  } catch (err) {
    console.error("Restore error:", err);
    res.status(500).json({ 
      message: "Failed to restore post",
      error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});
app.get("/api/admin/deleted-posts", authMiddleware(["admin"]), async (req, res) => {
  try {
    const posts = await Post.find({ deleted: true })
      .populate("author", "name email")
      .sort({ deletedAt: -1 });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch deleted posts" });
  }
});
app.put("/api/admin/comments/:id/restore", authMiddleware(["admin"]), async (req, res) => {
  try {
    const comment = await Comment.findOneAndUpdate(
      { _id: req.params.id, deleted: true },
      { $set: { deleted: false }, $unset: { deletedAt: 1 } },
      { new: true }
    );

    if (!comment) {
      return res.status(404).json({ 
        message: "Comment not found or already active"
      });
    }

    res.json({ 
      message: "Comment restored",
      commentId: comment._id
    });
  } catch (err) {
    console.error("Restore comment error:", err);
    res.status(500).json({ message: "Failed to restore comment" });
  }
});
// Add this after your existing auth routes
app.get('/api/auth/me', authMiddleware(), async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Author stats endpoint
app.get('/api/authors/:id/stats', authMiddleware(['author', 'admin']), async (req, res) => {
  try {
    const authorId = req.params.id;
    
    // Verify the requesting user is either the author or an admin
    if (req.user.role !== 'admin' && req.user.id !== authorId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const [posts, comments] = await Promise.all([
      Post.countDocuments({ author: authorId, deleted: false }),
      Comment.countDocuments({ post: { $in: await Post.find({ author: authorId }).distinct('_id') } })
    ]);

    // Get total likes across all posts
    const postsWithLikes = await Post.find({ author: authorId });
    const likes = postsWithLikes.reduce((sum, post) => sum + post.likes.length, 0);

    res.json({
      posts,
      likes,
      comments
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Reader stats endpoint
app.get('/api/readers/:id/stats', authMiddleware(['reader', 'admin']), async (req, res) => {
  try {
    const readerId = req.params.id;
    
    // Verify the requesting user is either the reader or an admin
    if (req.user.role !== 'admin' && req.user.id !== readerId) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const [comments, likedPosts] = await Promise.all([
      Comment.countDocuments({ author: readerId }),
      Post.countDocuments({ likes: readerId })
    ]);

    // For bookmarks, you'd need to implement a bookmark system first
    const bookmarks = 0; // Placeholder until you implement bookmarks

    res.json({
      likedPosts,
      comments,
      bookmarks
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});
// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
