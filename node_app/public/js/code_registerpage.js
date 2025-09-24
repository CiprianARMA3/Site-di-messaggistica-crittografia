document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const form = document.getElementById("signup-form");
  const errorBox = document.getElementById("client-error");
  const usernameInput = document.getElementById("username-box");
  const emailInput = document.getElementById("email-box");
  const passwordInput = document.getElementById("password-box");
  const togglePassword = document.getElementById("toggle-password");
  const versionGetter = document.getElementById("version-getter");
  const tosCheckbox = document.getElementById("tos-checkbox");

  // Version (footer)
  const versione = "customerhelp-feup@protonmail.com";
  if (versionGetter) versionGetter.innerText = versione;

  // Toggle password visibility
  if (togglePassword && passwordInput) {
    togglePassword.addEventListener("click", () => {
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        togglePassword.textContent = "Hide Password";
      } else {
        passwordInput.type = "password";
        togglePassword.textContent = "Show Password";
      }
    });
  }

  // Helpers
  function showError(msg) {
    if (!errorBox) return;
    errorBox.innerText = msg;
    errorBox.style.display = "block";
    errorBox.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  function clearError() {
    if (!errorBox) return;
    errorBox.innerText = "";
    errorBox.style.display = "none";
  }

  // Clear client error as soon as user types
  [usernameInput, emailInput, passwordInput].forEach((el) => {
    if (!el) return;
    el.addEventListener("input", clearError);
  });

  // Main client-side validation on submit
  if (form) {
    form.addEventListener("submit", (e) => {
      clearError();

      const username = (usernameInput?.value || "").trim();
      const email = (emailInput?.value || "").trim();
      const password = passwordInput?.value || "";

      // Username requirements
      if (username.length === 0) {
        e.preventDefault();
        showError("Username is required.");
        return;
      }
      if (username.length > 16) {
        e.preventDefault();
        showError("Username must be at most 16 characters.");
        return;
      }

      // Email requirements
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        e.preventDefault();
        showError("Please enter a valid email address (example: you@domain.com).");
        return;
      }

      // Password requirements
      if (password.length === 0) {
        e.preventDefault();
        showError("Password is required.");
        return;
      }
      if (password.length < 8) {
        e.preventDefault();
        showError("Password must be at least 8 characters long.");
        return;
      }
      if (password.length > 64) {
        e.preventDefault();
        showError("Password must be at most 64 characters.");
        return;
      }

      // ✅ TOS requirement
      if (!tosCheckbox?.checked) {
        e.preventDefault();
        showError("You must accept the Terms of Service to continue.");
        return;
      }
    });
  } else {
    console.error('Signup form not found: make sure your form has id="signup-form"');
  }
});
