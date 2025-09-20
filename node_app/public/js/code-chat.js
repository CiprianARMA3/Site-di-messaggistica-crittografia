// Modal logic
const addFriendBtn = document.getElementById('add-friend-btn');
const joinGroupBtn = document.getElementById('join-group-btn');
const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const closeBtn = document.querySelector('.close-btn');
const modalSubmit = document.getElementById('modal-submit');
const modalInput = document.getElementById('modal-input');

addFriendBtn.addEventListener('click', () => {
  modal.style.display = 'flex';
  modalTitle.textContent = 'Add Friend';
  modalInput.value = '';
});

joinGroupBtn.addEventListener('click', () => {
  modal.style.display = 'flex';
  modalTitle.textContent = 'Join Group';
  modalInput.value = '';
});

closeBtn.addEventListener('click', () => {
  modal.style.display = 'none';
});

modalSubmit.addEventListener('click', () => {
  const name = modalInput.value.trim();
  if (name) {
    alert(`${modalTitle.textContent}: ${name}`);
    modal.style.display = 'none';
  }
});

window.addEventListener('click', (e) => {
  if (e.target === modal) {
    modal.style.display = 'none';
  }
});

// Sidebar search
const sidebarSearch = document.getElementById("sidebar-search");
const chats = document.querySelectorAll(".chat");

sidebarSearch.addEventListener("input", () => {
  const query = sidebarSearch.value.toLowerCase();
  chats.forEach(chat => {
    const name = chat.querySelector("h4").textContent.toLowerCase();
    const lastMsg = chat.querySelector("p").textContent.toLowerCase();
    chat.style.display = (name.includes(query) || lastMsg.includes(query)) ? "flex" : "none";
  });
});

// Chat message search
const chatSearchToggle = document.getElementById("chat-search-toggle");
const chatSearch = document.getElementById("chat-search");
const chatSearchInput = document.getElementById("chat-search-input");
const messages = document.querySelectorAll(".messages .message");

chatSearchToggle.addEventListener("click", () => {
  chatSearch.style.display = chatSearch.style.display === "block" ? "none" : "block";
  chatSearchInput.value = "";
  messages.forEach(msg => msg.style.background = "");
});

chatSearchInput.addEventListener("input", () => {
  const query = chatSearchInput.value.toLowerCase();
  messages.forEach(msg => {
    const text = msg.textContent.toLowerCase();function jumpToMessage(searchTerm) {
    const chatMessages = document.querySelectorAll('.message');
    let firstMatch = null;

    chatMessages.forEach(msg => {
        const text = msg.textContent.toLowerCase();
        msg.classList.remove('highlighted');

        if (searchTerm && text.includes(searchTerm.toLowerCase())) {
            msg.classList.add('highlighted');

            if (!firstMatch) {
                firstMatch = msg;
            }
        }
    });

    if (firstMatch) {
        firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

    msg.style.background = (query && text.includes(query)) ? "rgba(0, 128, 255, 0.3)" : "";
  });
});

const chatSearchToggle2 = document.getElementById('chat-search-toggle');
const chatSearch2 = document.getElementById('chat-search');
const chatSearchInput2 = document.getElementById('chat-search-input');

chatSearchToggle2.addEventListener('click', () => {
  chatSearch2.classList.toggle('show');
  if (chatSearch2.classList.contains('show')) {
    chatSearchInput2.focus();
  }
});

function jumpToMessage(searchTerm) {
    const chatMessages = document.querySelectorAll('.message');
    let firstMatch = null;

    chatMessages.forEach(msg => {
        const text = msg.textContent.toLowerCase();
        msg.classList.remove('highlighted');

        if (searchTerm && text.includes(searchTerm.toLowerCase())) {
            msg.classList.add('highlighted');

            if (!firstMatch) {
                firstMatch = msg;
            }
        }
    });

    if (firstMatch) {
        firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}
function setUserStatus(userElement, isOnline) {
    const statusEl = userElement.querySelector('.status');
    if (!statusEl) return;

    if (isOnline) {
        statusEl.textContent = "Online";
        statusEl.classList.add("online");
        statusEl.classList.remove("offline");
    } else {
        statusEl.textContent = "Offline";
        statusEl.classList.add("offline");
        statusEl.classList.remove("online");
    }
}
