document.querySelector('.form-container').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent form from submitting the normal way

    const resetKey = document.getElementById('resetKey').value;
    const newPassword = document.getElementById('newPassword').value;

    fetch(this.action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resetKey, newPassword })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Your password has been reset successfully.');
            window.location.href = 'index.html'; // Redirect to login page
        } else {
            alert(data.message); // Display error message
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    });
});