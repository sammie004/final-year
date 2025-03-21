document.addEventListener('DOMContentLoaded', () => {
      const signupButton = document.querySelector(".sign-up");
      const originalText = signupButton.textContent;

      signupButton.addEventListener('click', async (e) => {
        e.preventDefault();

        // Disable the button and add a loading animation
        signupButton.disabled = true;
        signupButton.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>`

        // Get form values
        const username = document.querySelector("#username").value.trim();
        const email = document.querySelector("#email").value.trim();
        const password = document.querySelector("#password").value.trim();
        const role = document.querySelector("#role").value;
        const department = document.querySelector("#department").value.trim();

        if (!username || !email || !password || !role || !department) {
          alert("All fields are required");
          signupButton.disabled = false;
          signupButton.textContent = originalText;
          return;
        }

        try {
          const response = await fetch('http://localhost:3000/sign-up', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, role, department })
          });

          console.log("Response Status:", response.status);

          const data = await response.json();

          if (response.status === 409) {
            alert("This user already exists.");
          } else if (response.ok) {
            alert(data.message || "Sign up successful!");
            console.log(`Welcome user ${username}`);
            setTimeout(() => {
              window.location.href = "/login";
            }, 2000);
          } else {
            console.error("Sign up error:", data);
            alert("An error occurred during sign-up.");
          }
        } catch (error) {
          console.error("Network error:", error);
          alert("Failed to connect to the server.");
        } finally {
          // Re-enable the button and restore its text
          signupButton.disabled = false;
          signupButton.textContent = originalText;
        }
      });
    });
