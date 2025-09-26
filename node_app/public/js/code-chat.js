// public/js/code-chat.js
document.addEventListener("DOMContentLoaded", () => {
  const csrfToken = document.getElementById("csrfToken")?.value;

  // ---------- Helpers ----------
  function $(sel) { return document.querySelector(sel); }
  function $all(sel) { return Array.from(document.querySelectorAll(sel)); }

  function showNotification(message, type = "success") {
    const box = document.getElementById("notification");
    if (!box) return;
    box.textContent = message;
    box.className = `notification ${type} show`;
    setTimeout(() => box.classList.remove("show"), 3000);
  }

  // ---------- Elements (safe lookup) ----------
  const chatView = document.getElementById("chat-view");
  const chatHeaderImg = document.querySelector(".chat-header img");
  const chatHeaderName = document.querySelector(".chat-header h4");
  const chatHeaderStatus = document.querySelector(".chat-header .status");
  const chatSearchToggle = document.getElementById("chat-search-toggle");
  const chatSearchBox = document.getElementById("chat-search"); // hidden search UI
  const chatSearchInput = document.getElementById("chat-search-input");
  // Sidebar search might be duplicated in your template -> attach to all
  const sidebarSearchInputs = document.querySelectorAll('input#sidebar-search');
  const requestsBtn = document.getElementById("requests");
  const requestsModal = document.getElementById("requests-modal");
  const modal = document.getElementById("modal");
  const modalTitle = document.getElementById("modal-title");
  const modalInput = document.getElementById("modal-input");
  const modalSubmit = document.getElementById("modal-submit");
  const incomingRequests = document.getElementById("incoming-requests");
  const addFriendBtn = document.getElementById("add-friend-btn");
  const joinGroupBtn = document.getElementById("join-group-btn");

  // Small state
  let lastFriends = []; // latest friends array returned by API
  let activeChatIndex = -1;

  // ---------- Modals ----------
  if (addFriendBtn) addFriendBtn.addEventListener("click", () => {
    if (!modal) return;
    modal.style.display = "flex";
    modalTitle.textContent = "Add Friend";
    modalInput.value = "";
  });
  if (joinGroupBtn) joinGroupBtn.addEventListener("click", () => {
    if (!modal) return;
    modal.style.display = "flex";
    modalTitle.textContent = "Join Group";
    modalInput.value = "";
  });
  if (modal) {
    const close = modal.querySelector(".close-btn");
    if (close) close.addEventListener("click", () => (modal.style.display = "none"));
  }
  if (requestsModal) {
    requestsModal.querySelectorAll(".close-btn").forEach(btn =>
      btn.addEventListener("click", () => (requestsModal.style.display = "none"))
    );
  }
  window.addEventListener("click", e => {
    if (e.target === modal) modal.style.display = "none";
    if (e.target === requestsModal) requestsModal.style.display = "none";
  });
  
if (modalSubmit) {
  modalSubmit.addEventListener("click", async () => {
    const action = modalTitle.textContent;
    const value = modalInput.value.trim();
    if (!value) return;

    if (action === "Add Friend") {
      try {
        const res = await fetch("/friends/request", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(csrfToken ? { "CSRF-Token": csrfToken } : {})
          },
          body: JSON.stringify({ friendId: value })
        });
        const data = await res.json();
        if (data.success) {
          showNotification("✅ Friend request sent!");
          modal.style.display = "none";
        } else {
          showNotification("⚠️ " + (data.error || "Failed to send"), "error");
        }
      } catch (err) {
        console.error("Add friend error:", err);
      }
    }

    if (action === "Join Group") {
      // TODO: implement group join logic
      console.log("Joining group with code:", value);
      modal.style.display = "none";
    }
  });
}
  // ---------- Friend Requests API ----------
  async function loadRequests() {
    if (!requestsModal) return;
    try {
      const res = await fetch("/friends/requests");
      const data = await res.json();
      const list = requestsModal.querySelector(".requests-list");
      if (!list) return;
      list.innerHTML = "";
      const requests = data.requests || [];
      if (!requests.length) {
        list.innerHTML = `<p>No requests</p>`;
      } else {
        requests.forEach(req => {
          const div = document.createElement("div");
          div.className = "request";
          div.innerHTML = `
            <span>${req.fromUsername}</span>
            <div class="request-actions">
              <button class="accept-btn" data-id="${req.fromId}">Accept</button>
              <button class="decline-btn" data-id="${req.fromId}">Decline</button>
            </div>
          `;
          div.querySelector(".accept-btn").addEventListener("click", async e => {
            const fromId = e.target.getAttribute("data-id");
            await fetch("/friends/accept", {
              method: "POST",
              headers: { "Content-Type": "application/json", ...(csrfToken ? { "CSRF-Token": csrfToken } : {}) },
              body: JSON.stringify({ fromId })
            });
            await loadRequests();
            await loadFriends();
          });
          div.querySelector(".decline-btn").addEventListener("click", async e => {
            const fromId = e.target.getAttribute("data-id");
            await fetch("/friends/decline", {
              method: "POST",
              headers: { "Content-Type": "application/json", ...(csrfToken ? { "CSRF-Token": csrfToken } : {}) },
              body: JSON.stringify({ fromId })
            });
            await loadRequests();
          });
          list.appendChild(div);
        });
      }
      updateRequestCounter(requests.length);
    } catch (err) {
      console.error("loadRequests error", err);
    }
  }
  if (requestsBtn) requestsBtn.addEventListener("click", () => {
    if (!requestsModal) return;
    requestsModal.style.display = "flex";
    loadRequests();
  });

  async function updateRequestCounter(count) {
    try {
      if (typeof count === "number") {
        incomingRequests.textContent = count > 0 ? count : "";
        incomingRequests.style.display = count > 0 ? "inline-block" : "none";
        return;
      }
      const res = await fetch("/friends/requests");
      const data = await res.json();
      const c = (data.requests || []).length;
      incomingRequests.textContent = c > 0 ? c : "";
      incomingRequests.style.display = c > 0 ? "inline-block" : "none";
    } catch (err) {
      console.error("updateRequestCounter error", err);
    }
  }

  // ---------- Friend list (sidebar) ----------
  async function loadFriends() {
  try {
    const res = await fetch("/friends/list");
    const data = await res.json();
    const chatList = document.querySelector(".chat-list");
    if (!chatList) return;
    const buttons = chatList.querySelector(".chat-buttons"); // keep buttons
    const fresh = Array.isArray(data.friends) ? data.friends : [];

    // ✅ preserve socket-updated online status if available
    lastFriends = fresh.map(f => {
      const cached = lastFriends.find(old => String(old.id) === String(f.id));
      return {
        ...f,
        online: cached ? cached.online : f.online, // trust cache if sockets updated it
      };
    });

    // render fresh
    chatList.innerHTML = "";
    lastFriends.forEach((f, i) => {
      const div = document.createElement("div");
      div.className = "chat";
      div.setAttribute("data-friend-id", String(f.id));
      const onlineClass = f.online ? "online" : "offline";
      div.innerHTML = `
        <img src="${f.pfp}" alt="Contact" class="user-img">
        <div class="chat-info">
          <h4 class="name-user ${onlineClass}">${f.username}</h4>
          <p class="last-message">${f.lastMessage || "ultimo messaggio placeholder"}</p>
        </div>
        <span class="time">${f.lastActive || ""}</span>
      `;
      // click activates the chat
      div.addEventListener("click", () => {
        activateFriendChat(f, i);
        // visual selection
        document.querySelectorAll(".chat-list .chat").forEach(el => el.classList.remove("active"));
        div.classList.add("active");
      });
      chatList.appendChild(div);
    });

    if (buttons) chatList.appendChild(buttons);

    // Auto-activate friend:
    const currentFriendId = document.body.dataset.friendId;
    if (currentFriendId) {
      const idx = lastFriends.findIndex(ff => String(ff.id) === String(currentFriendId));
      if (idx !== -1) {
        activateFriendChat(lastFriends[idx], idx);
        const el = document.querySelector(`.chat-list .chat[data-friend-id="${currentFriendId}"]`);
        if (el) {
          document.querySelectorAll(".chat-list .chat").forEach(e => e.classList.remove("active"));
          el.classList.add("active");
        }
        return;
      }
    }

    if (lastFriends.length > 0) {
      // no friend selected -> activate first friend
      activateFriendChat(lastFriends[0], 0);
      const firstEl = chatList.querySelector(".chat");
      if (firstEl) {
        document.querySelectorAll(".chat-list .chat").forEach(e => e.classList.remove("active"));
        firstEl.classList.add("active");
      }
    } else {
      // clear chat view when no friends
      if (chatView) chatView.innerHTML = `<p class="empty">Select a user to chat with</p>`;
    }
  } catch (err) {
    console.error("loadFriends error", err);
  }
}


  // ---------- Sidebar search (friend list) ----------
  function filterFriendList(query) {
    const q = String(query || "").trim().toLowerCase();
    document.querySelectorAll(".chat-list .chat").forEach(chatEl => {
      const name = chatEl.querySelector(".name-user")?.textContent?.toLowerCase() || "";
      const lastMsg = chatEl.querySelector(".last-message")?.textContent?.toLowerCase() || "";
      const show = !q || name.includes(q) || lastMsg.includes(q);
      chatEl.style.display = show ? "flex" : "none";
    });
  }
  // attach to all possible sidebar search inputs (in case of duplicates)
  sidebarSearchInputs.forEach(input => {
    input.addEventListener("input", e => filterFriendList(e.target.value));
  });

  // ---------- Chat search (messages) ----------

if (chatSearchToggle && chatSearchBox && chatSearchInput) {
  chatSearchToggle.addEventListener("click", () => {
    chatSearchBox.classList.toggle("active"); // toggle class

    if (chatSearchBox.classList.contains("active")) {
      chatSearchInput.focus();
    } else {
      chatSearchInput.value = "";
      highlightMessages("");
    }
  });

  chatSearchInput.addEventListener("input", e => {
    highlightMessages(e.target.value);
  });
}

function highlightMessages(query) {
  if (!chatView) return;
  const q = String(query || "").trim().toLowerCase();
  const messages = chatView.querySelectorAll(".message");
  let firstMatch = null;

  messages.forEach(msg => {
    const text = msg.textContent.toLowerCase();
    if (q && text.includes(q)) {
      msg.classList.add("matched");
      msg.style.background = "rgba(0,128,255,0.18)";
      if (!firstMatch) firstMatch = msg;
    } else {
      msg.classList.remove("matched");
      msg.style.background = "";
    }
  });

  if (firstMatch) {
    firstMatch.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

  // ---------- Settings toggle (ellipsis) ----------
  const ellipsisIcon = document.querySelector(".chat-actions .fa-ellipsis-v");
  const settingsView = document.getElementById("settings-view");
  const backBtn = document.querySelector("#settings-view .back-to-chat");
  if (ellipsisIcon && chatView && settingsView) {
    ellipsisIcon.addEventListener("click", () => {
      const open = settingsView.classList.toggle("active");
      chatView.classList.toggle("hidden", open);
      settingsView.setAttribute("aria-hidden", !open);
    });
    if (backBtn) backBtn.addEventListener("click", () => {
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

  // ---------- Messages (load/send) ----------
  const messageInput = document.querySelector(".chat-footer input[type=text]");
  const sendBtn = document.querySelector(".chat-footer .send-btn");
  const userId = Number(document.body.dataset.userId || 0);

    // ---------- Socket.io presence ----------
    const socket = io();
    
    socket.on("new_message", msg => {
  console.log("💬 New message:", msg);

  // Only display if the chat with this friend is currently open
  if (currentFriendId && Number(currentFriendId) === Number(msg.from)) {
    const msgDiv = document.createElement("div");
    msgDiv.classList.add("msg", "friend");
    msgDiv.textContent = `${msg.content} (${msg.time})`;
    chatView.appendChild(msgDiv);
    chatView.scrollTop = chatView.scrollHeight;
  } else {
    // Optionally show a notification or highlight the friend in the sidebar
    console.log("📩 Message received from another friend:", msg.from);
  }
});

  socket.on("connect", () => {
    if (userId) socket.emit("auth", { userId });
  });

  socket.on("user_online", (id) => {
    updateFriendStatus(id, true);
  });

  socket.on("new_message", (msg) => {
  const currentFriendId = document.body.dataset.friendId;
  if (String(msg.from) === String(currentFriendId)) {
    appendMessage({
      senderId: msg.from,
      content: msg.content,
      type: msg.type,
      time: msg.time
    });
    if (chatView) chatView.scrollTop = chatView.scrollHeight;
  } else {
    // optional: show a sidebar "new message" indicator
    const chatEl = document.querySelector(`.chat-list .chat[data-friend-id="${msg.from}"]`);
    if (chatEl) chatEl.classList.add("unread");
  }
});

  socket.on("user_offline", (id) => {
    updateFriendStatus(id, false);
  });

function updateFriendStatus(friendId, online) {
  // keep cache in sync
  const idx = lastFriends.findIndex(f => String(f.id) === String(friendId));
  if (idx !== -1) {
    lastFriends[idx].online = online;
  }

  // Sidebar
  const el = document.querySelector(`.chat-list .chat[data-friend-id="${friendId}"]`);
  if (el) {
    const nameEl = el.querySelector(".name-user");
    if (nameEl) {
      nameEl.classList.toggle("online", online);
      nameEl.classList.toggle("offline", !online);
    }
  }

  // Header
  if (String(document.body.dataset.friendId) === String(friendId)) {
    if (chatHeaderStatus) {
      chatHeaderStatus.textContent = online ? "online" : "offline";
      chatHeaderStatus.classList.toggle("online", online);
      chatHeaderStatus.classList.toggle("offline", !online);
    }
  }
}

  async function loadMessages() {
    const friendId = document.body.dataset.friendId;
    if (!friendId) return;
    try {
      const res = await fetch(`/chat/${friendId}`);
      const data = await res.json();
      if (!chatView) return;
      chatView.innerHTML = "";
      (data.messages || []).forEach(m => appendMessage(m));
      chatView.scrollTop = chatView.scrollHeight;
    } catch (err) {
      console.error("loadMessages error", err);
    }
  }

  function appendMessage(msg) {
    if (!chatView) return;
    const div = document.createElement("div");
    div.className = "message " + (msg.senderId === userId ? "outgoing" : "incoming");
    const p = document.createElement("p");
    p.innerHTML = `${msg.content} <span class="time">${msg.time || ""}</span>`;
    div.appendChild(p);
    chatView.appendChild(div);
  }

  async function sendMessage() {
    if (!messageInput) return;
    const content = messageInput.value.trim();
    const friendId = document.body.dataset.friendId;
    if (!content || !friendId) return;
    try {
      const res = await fetch(`/chat/${friendId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(csrfToken ? { "CSRF-Token": csrfToken } : {}) },
        body: JSON.stringify({ content, type: "text" })
      });
      const data = await res.json();
      if (data.success) {
        appendMessage({ senderId: userId, content, type: "text", time: new Date().toLocaleTimeString() });
        messageInput.value = "";
        if (chatView) chatView.scrollTop = chatView.scrollHeight;
      } else {
        console.warn("sendMessage server response:", data);
      }
    } catch (err) {
      console.error("sendMessage error", err);
    }
  }
  if (sendBtn) sendBtn.addEventListener("click", sendMessage);
  if (messageInput) messageInput.addEventListener("keypress", e => { if (e.key === "Enter") sendMessage(); });

  // ---------- Status updater ----------
  // let statusUpdaterId = null;
  // function startStatusUpdater(friendId) {
  //   if (statusUpdaterId) clearInterval(statusUpdaterId);
  //   const headerStatus = chatHeaderStatus;
  //   statusUpdaterId = setInterval(async () => {
  //     try {
  //       const res = await fetch(`/friends/status/${friendId}`);
  //       const data = await res.json();
  //       if (!headerStatus) return;
  //       if (data.online) {
  //         headerStatus.textContent = "online";
  //         headerStatus.classList.remove("offline");
  //         headerStatus.classList.add("online");
  //       } else {
  //         headerStatus.textContent = "offline";
  //         headerStatus.classList.remove("online");
  //         headerStatus.classList.add("offline");
  //       }
  //     } catch (err) {
  //       console.error("status update error", err);
  //     }
  //   }, 5000);
  // }

  // ---------- Activate friend chat ----------
  function activateFriendChat(friend, idx = 0) {
    if (!friend) return;
    document.body.dataset.friendId = friend.id;
    activeChatIndex = idx;
    if (chatHeaderImg) chatHeaderImg.src = friend.pfp || "/images/blank.png";
    if (chatHeaderName) chatHeaderName.textContent = friend.username || "Unknown";
    if (chatHeaderStatus) {
      if (friend.online) {
        chatHeaderStatus.textContent = "online";
        chatHeaderStatus.classList.remove("offline");
        chatHeaderStatus.classList.add("online");
      } else {
        chatHeaderStatus.textContent = "offline";
        chatHeaderStatus.classList.remove("online");
        chatHeaderStatus.classList.add("offline");
      }
    }
    // startStatusUpdater(friend.id);
    if (chatView) chatView.innerHTML = "";
    loadMessages();
  }

  // ---------- Init ----------
(async function init() {
  updateRequestCounter();
  await loadFriends();
  // keep messages fresh
  setInterval(loadMessages, 3000);

  // keep sidebar presence fresh (in case socket missed something)
})();

});
