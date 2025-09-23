document.addEventListener("DOMContentLoaded", () => {
  const buttons = document.querySelectorAll(".tab-button");
  const contents = document.querySelectorAll(".tab-content");
  let activeContent = document.querySelector(".tab-content.active");

  buttons.forEach(button => {
    button.addEventListener("click", () => {
      const targetId = button.dataset.tab;
      const target = document.getElementById(targetId);

      if (target === activeContent) return; // already open, do nothing

      // deactivate buttons
      buttons.forEach(b => b.classList.remove("active"));
      button.classList.add("active");

      if (activeContent) {
        // animate out current
        activeContent.classList.remove("active");
        activeContent.classList.add("exiting");

        // wait for animation, then fully hide
        setTimeout(() => {
          activeContent.classList.remove("exiting");
          activeContent.style.display = "none";

          // now show the new one
          target.style.display = "block";
          setTimeout(() => target.classList.add("active"), 10);
          activeContent = target;
        }, 350); // matches CSS transition
      } else {
        // first load (no active yet)
        target.style.display = "block";
        setTimeout(() => target.classList.add("active"), 10);
        activeContent = target;
      }
    });
  });
});


document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("pfp");
  const previewImg = document.getElementById("profile-preview");

  if (fileInput && previewImg) {
    fileInput.addEventListener("change", (event) => {
      const file = event.target.files[0];
      if (file && file.type.startsWith("image/")) {
        const reader = new FileReader();
        reader.onload = (e) => {
          previewImg.src = e.target.result; // Set preview
        };
        reader.readAsDataURL(file);
      }
    });
  }
});

