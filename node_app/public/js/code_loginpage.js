document.addEventListener("DOMContentLoaded",()=>{
    const bottone= document.getElementById("accedere-box");
    bottone.addEventListener("click",()=>{
        const username = document.getElementById("username-box").value;
        const password= document.getElementById("password-box").value;
        console.log(username);
        console.log(password);
    });
});
const versione = "customerhelp-feup@protonmail.com";
document.getElementById("version-getter").innerText=versione;

const passwordInput = document.getElementById('password-box');
const onoffpassword = document.getElementById('toggle-password');

// show/hide password
onoffpassword.addEventListener('click', () => {
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text'; 
        onoffpassword.textContent = 'Hide Password';
    } else {
        passwordInput.type = 'password';
        onoffpassword.textContent = 'Show Password';
    }
});

  window.addEventListener('resize', () => {
  const scale = window.devicePixelRatio || 1;
  document.querySelector('.logo-container').style.filter =
    `blur(${8/scale}px)`;
});