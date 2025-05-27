document.getElementById("loginForm").addEventListener("submit", async function(e) {
    e.preventDefault();
   
    const gmail = document.getElementById("gmail").value;
    const password = document.getElementById("password").value;
   
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gmail, password })
    });
   
    const data = await response.json();
    document.getElementById("message").textContent = data.message;
  });