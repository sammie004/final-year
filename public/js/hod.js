document.addEventListener('DOMContentLoaded', () => {
  const username = localStorage.getItem("username")
  console.log(username)
  const loggedIn = document.querySelector(".span")
  loggedIn.textContent = 'welcome'+' '+ username
    const logoutBtn = document.querySelector('.logout');
    if (!logoutBtn) {
      console.error("Logout button not found!");
      return;
    }
    logoutBtn.addEventListener('click',(e)=>{
        e.preventDefault()
        logout()
    })
  });

  function logout() {
    // Remove the token from localStorage
    localStorage.removeItem("token");
    
    // Optionally remove any other related items
    localStorage.removeItem("student_id");
    localStorage.removeItem("username")
    
    // Redirect to a login or home page
    window.location.href = 'login.html';
  }
  
  