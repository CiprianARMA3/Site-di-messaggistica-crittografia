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
    if(name) {
        alert(`${modalTitle.textContent}: ${name}`);
        modal.style.display = 'none';
    }
});

// Close modal on click outside content
window.addEventListener('click', (e) => {
    if(e.target === modal){
        modal.style.display = 'none';
    }
});