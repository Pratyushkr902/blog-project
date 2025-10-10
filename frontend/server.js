const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from 'public' folder
app.use(express.static("public"));

// Fallback for single page apps (optional)
app.get("*", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
