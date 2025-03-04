document.addEventListener('DOMContentLoaded', () => {
    const username = document.querySelector(".username");
    const logoutBtn = document.querySelector(".logout");
    const user = localStorage.getItem("username");
    username.textContent = user || "Guest";

    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      alert(`you clicked`);
      logout();
      window.location.href = '/login';
    });

    // Polling for notifications every 3 seconds
    setInterval(async () => {
      try {
        const response = await fetch('http://localhost:3000/notifications', {
          method: 'GET',
          headers: {
            // "Content-Type": "application/json", // Optional for GET
            "Authorization": "Bearer " + localStorage.getItem("token")
          },
          credentials: 'include'
        });

        if (!response.ok) {
          throw new Error("Failed to fetch notifications");
        }

        const notifications = await response.json();

        // Clear existing notifications
        const notifContainer = document.getElementById("notifContainer");
        notifContainer.innerHTML = '';

        // Check if there are notifications
        if (notifications.length > 0) {
          notifications.forEach(notification => {
            // Create a div for each notification
            const notifDiv = document.createElement("div");
            notifDiv.classList.add("notification");

            // Link to request details using notification.request_id
            notifDiv.innerHTML = `
              <p>${notification.message}</p>
              <a href="/requests/${notification.request_id}">View Details</a>
            `;
            notifContainer.appendChild(notifDiv);

            // Automatically hide after 5 seconds
            setTimeout(() => {
              notifDiv.remove();
            }, 5000);
          });
        }
      } catch (error) {
        console.error('Error fetching notifications:', error);
      }
    }, 3000); // Poll every 3000 milliseconds (3 seconds)
  });

  function logout(){
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("UserID");
    localStorage.removeItem("role");
  }