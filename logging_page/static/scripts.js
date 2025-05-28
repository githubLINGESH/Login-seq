// static/scripts.js
document.getElementById("loginForm").addEventListener("submit", async function(e) {
    e.preventDefault(); // Prevent default form submission

    const gmail = document.getElementById("gmail").value;
    const password = document.getElementById("password").value;
    const messageElement = document.getElementById("message");

    // Clear previous messages
    messageElement.textContent = '';
    messageElement.style.color = 'black'; // Reset color

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ gmail, password })
        });
        
        const data = await response.json();
        
        messageElement.textContent = data.message;

        if (response.ok) { // Status codes 200-299 indicate success
            messageElement.style.color = 'green';
            // If login is successful and a redirect URL is provided, navigate there
            if (data.redirect) {
                window.location.href = data.redirect;
            }
        } else { // Handle HTTP errors (e.g., 400, 401, 403)
            messageElement.style.color = 'red';
        }
    } catch (error) {
        console.error('Error during login fetch:', error);
        messageElement.textContent = 'An unexpected error occurred. Please try again.';
        messageElement.style.color = 'red';
    }
});
