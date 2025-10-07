<!DOCTYPE html>
<html>
<head>
  <title>Jovial Flames</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <h1>Welcome to Jovial Flames</h1>

  <script src="script.js">/</script> Example API call to your Render backend
fetch("https://jovial-flames-api1.onrender.com/api/signup-request-otp", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "test@example.com" })
})
.then(res => res.json())
.then(data => console.log(data));

</body>
</html>
