
  window.addEventListener('resize', () => {
  const scale = window.devicePixelRatio || 1;
  document.querySelector('.logo-container').style.filter =
    `blur(${8/scale}px)`;
});