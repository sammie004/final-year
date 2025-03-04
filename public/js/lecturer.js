document.addEventListener('DOMContentLoaded',()=>{
    const username = document.querySelector(".username")
    const logoutBtn = document.querySelector(".logout")
    const name = localStorage.getItem("username")
    username.textContent = name

    logoutBtn.addEventListener('click',(e)=>{
        e.preventDefault()
        alert(`you clicked`)
        logout()
    })
})
function logout() {
    // Remove the token from localStorage
    localStorage.removeItem("token");
    
    // Optionally remove any other related items
    localStorage.removeItem("student_id");
    localStorage.removeItem("username")
    localStorage.removeItem("User ID")
    // Redirect to a login or home page
    window.location.href = '/login';
  }