document.addEventListener('DOMContentLoaded', () => {
    const signup = document.querySelector(".sign-up");

    signup.addEventListener('click', async (e) => {
        e.preventDefault();
        
        // Get updated values here
        const username = document.querySelector("#username").value;
        const email = document.querySelector("#email").value;
        const password = document.querySelector("#password").value;
        const role = document.querySelector("#role").value;
        const department = document.querySelector("#department").value;

        if (!username || !email || !password || !role || !department) {
            alert("Those fields are required");
            return;
        } else {
            const response = await fetch('http://localhost:3000/sign-up', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password, role, department })
            });
            const data = await response.json();

            if (response.status === 409) {
                alert("this user already exists");
            } else if (response.ok) {
                alert("Sign up successful");
                console.log("Sign up successful");
                console.log(`Welcome user ${username}`);
                setTimeout(() => {
                    window.location.href = "/login";
                }, 2000);
            } else {
                // Log any other error message from the response
                console.error("Sign up error:", data);
            }
        }
    });
});
