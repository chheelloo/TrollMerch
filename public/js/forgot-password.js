document.querySelector('.form-container').addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent default form submission

    const email = document.getElementById('email').value;

    try {
        const response = await fetch('/send-password-reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email }),
        });

        const result = await response.json();
        
        if (response.ok) {
            // If the response contains the redirect URL, redirect the user
            if (result.redirectUrl) {
                window.location.href = result.redirectUrl; // Redirect to reset-password.html
            } else {
                alert(result.message); // Show success message
            }
        } else {
            alert(result.message); // Show error message
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Something went wrong. Please try again.');
    }
});