// public/js/code-chat.js
document.addEventListener("DOMContentLoaded", () => {
  const csrfToken = document.getElementById("csrfToken")?.value;

  // ---------------- MODALS ----------------
  const addFriendBtn = document.getElementById("add-friend-btn");
  const joinGroupBtn = document.getElementById("join-group-btn");
  const modal = document.getElementById("modal");
  const modalTitle = document.getElementById("modal-title");
  const modalInput = document.getElementById("modal-input");
  const modalSubmit = document.getElementById("modal-submit");
  const modalClose = modal.querySelector(".close-btn");

  const requestsBtn = document.getElementById("requests");
  const requestsModal = document.getElementById("requests-modal");
  const requestsCloseBtns = requestsModal.querySelectorAll(".close-btn");

  // Open "Add Friend" modal
  addFriendBtn.addEventListener("click", () => {
    modal.style.display = "flex";
    modalTitle.textContent = "Add Friend";
    modalInput.value = "";
  });

  // Open "Join Group" modal
  joinGroupBtn.addEventListener("click", () => {
    modal.style.display = "flex";
    modalTitle.textContent = "Join Group";
    modalInput.value = "";
  });

  // Close modals
  modalClose.addEventListener("click", () => (modal.style.display = "none"));
  requestsCloseBtns.forEach(btn =>
    btn.addEventListener("click", () => (requestsModal.style.display = "none"))
  );
  window.addEventListener("click", e => {
    if (e.target === modal) modal.style.display = "none";
    if (e.target === requestsModal) requestsModal.style.display = "none";
  });

  // ---------------- SEND FRIEND REQUEST ----------------
modalSubmit.addEventListener("click", async () => {
  const friendId = modalInput.value.trim(); // ✅ expects ID
  if (!friendId) {
    alert("Please enter a valid friend ID.");
    return;
  }

  try {
    // 🔎 Pre-check friend list before sending
    const friendsRes = await fetch("/friends/list");
    const friendsData = await friendsRes.json();
    const alreadyFriend = friendsData.friends.some(f => String(f.id) === String(friendId));

    if (alreadyFriend) {
      alert("❌ You are already friends with this user.");
      return; // ⛔ do not send request
    }

    // If not already a friend, proceed with request
    const res = await fetch("/friends/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken ? { "CSRF-Token": csrfToken } : {})
      },
      body: JSON.stringify({ friendId })
    });

    const data = await res.json();

    if (data.success) {
      alert("✅ Friend request sent!");
      modal.style.display = "none";
      updateRequestCounter(); // refresh counter
    } else {
      alert("❌ Error: " + (data.error || "Something went wrong"));
    }
  } catch (err) {
    console.error(err);
    alert("⚠️ Request failed");
  }
});

  // ---------------- LOAD REQUESTS ----------------
  async function loadRequests() {
    try {
      const res = await fetch("/friends/requests");
      const data = await res.json();
      const list = requestsModal.querySelector(".requests-list");
      list.innerHTML = "";

      if (!data.requests.length) {
        list.innerHTML = `<p>No requests</p>`;
      } else {
        data.requests.forEach(req => {
          const div = document.createElement("div");
          div.classList.add("request");
          div.innerHTML = `
            <span>${req.fromUsername}</span>
            <div class="request-actions">
              <button class="accept-btn" data-id="${req.fromId}">Accept</button>
              <button class="decline-btn" data-id="${req.fromId}">Decline</button>
            </div>
          `;

          // Accept
          div.querySelector(".accept-btn").addEventListener("click", async e => {
            const fromId = e.target.getAttribute("data-id");
            await fetch("/friends/accept", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                ...(csrfToken ? { "CSRF-Token": csrfToken } : {})
              },
              body: JSON.stringify({ fromId })
            });
            loadRequests();
            loadFriends();
          });

          // Decline
          div.querySelector(".decline-btn").addEventListener("click", async e => {
            const fromId = e.target.getAttribute("data-id");
            await fetch("/friends/decline", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                ...(csrfToken ? { "CSRF-Token": csrfToken } : {})
              },
              body: JSON.stringify({ fromId })
            });
            loadRequests();
          });

          list.appendChild(div);
        });
      }

      updateRequestCounter(data.requests.length);
    } catch (err) {
      console.error(err);
    }
  }

  // Open Requests modal
  requestsBtn.addEventListener("click", () => {
    requestsModal.style.display = "flex";
    loadRequests();
  });

  // ---------------- FRIEND LIST ----------------
  async function loadFriends() {
    try {
      const res = await fetch("/friends/list");
      const data = await res.json();
      const chatList = document.querySelector(".chat-list");

      // Keep the Add Friend / Join Group / Requests buttons
      const buttons = chatList.querySelector(".chat-buttons");

      chatList.innerHTML = "";
      data.friends.forEach(f => {
        const div = document.createElement("div");
        div.classList.add("chat");
        div.innerHTML = `
          <img src="${f.pfp}" alt="Contact" class="user-img">
          <div class="chat-info">
            <h4 class="name-user">${f.username}</h4>
            <p class="last-message">ultimo messaggio placeholder</p>
          </div>
          <span class="time">10:45</span>
        `;
        chatList.appendChild(div);
      });

      if (buttons) chatList.appendChild(buttons);
    } catch (err) {
      console.error(err);
    }

  }

  // ---------------- REQUEST COUNTER ----------------
  const requestCounter = document.getElementById("incoming-requests");

  function updateRequestCounter(count) {
    if (typeof count === "number") {
      requestCounter.textContent = count > 0 ? count : "";
      requestCounter.style.display = count > 0 ? "inline-block" : "none";
      return;
    }

    fetch("/friends/requests")
      .then(res => res.json())
      .then(data => {
        const c = data.requests.length;
        requestCounter.textContent = c > 0 ? c : "";
        requestCounter.style.display = c > 0 ? "inline-block" : "none";
      })
      .catch(err => console.error("Failed to update request counter:", err));
  }

  setInterval(updateRequestCounter, 10000);

  // ---------------- SEARCH ----------------
  const sidebarSearch = document.getElementById("sidebar-search");
  sidebarSearch.addEventListener("input", () => {
    const query = sidebarSearch.value.toLowerCase();
    document.querySelectorAll(".chat").forEach(chat => {
      const name = chat.querySelector("h4")?.textContent.toLowerCase() || "";
      const lastMsg = chat.querySelector("p")?.textContent.toLowerCase() || "";
      chat.style.display =
        name.includes(query) || lastMsg.includes(query) ? "flex" : "none";
    });
  });

  // ---------------- CHAT SEARCH ----------------
  const chatSearchToggle = document.getElementById("chat-search-toggle");
  const chatSearch = document.getElementById("chat-search");
  const chatSearchInput = document.getElementById("chat-search-input");

  chatSearchToggle.addEventListener("click", () => {
    chatSearch.style.display =
      chatSearch.style.display === "block" ? "none" : "block";
    chatSearchInput.value = "";
    document
      .querySelectorAll(".messages .message")
      .forEach(msg => (msg.style.background = ""));
  });

  chatSearchInput.addEventListener("input", () => {
    const query = chatSearchInput.value.toLowerCase();
    document.querySelectorAll(".messages .message").forEach(msg => {
      const text = msg.textContent.toLowerCase();
      msg.style.background =
        query && text.includes(query) ? "rgba(0,128,255,0.3)" : "";
    });
  });

  // ---------------- SETTINGS TOGGLE ----------------
  const ellipsisIcon = document.querySelector(".chat-actions .fa-ellipsis-v");
  const chatView = document.getElementById("chat-view");
  const settingsView = document.getElementById("settings-view");
  const backBtn = document.querySelector("#settings-view .back-to-chat");

  if (ellipsisIcon && chatView && settingsView) {
    ellipsisIcon.addEventListener("click", () => {
      const open = settingsView.classList.toggle("active");
      chatView.classList.toggle("hidden", open);
      settingsView.setAttribute("aria-hidden", !open);
      if (open)
        settingsView.querySelector("input, button, [tabindex]")?.focus();
    });

    backBtn.addEventListener("click", () => {
      settingsView.classList.remove("active");
      chatView.classList.remove("hidden");
      settingsView.setAttribute("aria-hidden", "true");
      ellipsisIcon.focus();
    });

    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && settingsView.classList.contains("active")) {
        settingsView.classList.remove("active");
        chatView.classList.remove("hidden");
        settingsView.setAttribute("aria-hidden", "true");
        ellipsisIcon.focus();
      }
    });
  }
  

  // ---------------- INIT ----------------
  updateRequestCounter();
  loadFriends();
});

