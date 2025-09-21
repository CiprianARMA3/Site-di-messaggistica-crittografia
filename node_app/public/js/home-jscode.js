
const cities = [
  "Amsterdam",   // Netherlands
  "Andorra la Vella", // Andorra
  "Athens",      // Greece
  "Belgrade",    // Serbia
  "Berlin",      // Germany
  "Bern",        // Switzerland
  "Bratislava",  // Slovakia
  "Brussels",    // Belgium
  "Bucharest",   // Romania
  "Budapest",    // Hungary
  "Chisinau",    // Moldova
  "Copenhagen",  // Denmark
  "Dublin",      // Ireland
  "Helsinki",    // Finland
  "Lisbon",      // Portugal
  "Ljubljana",   // Slovenia
  "London",      // United Kingdom
  "Luxembourg",  // Luxembourg
  "Madrid",      // Spain
  "Monaco",      // Monaco
  "Moscow",      // Russia 
  "Oslo",        // Norway
  "Paris",       // France
  "Podgorica",   // Montenegro
  "Prague",      // Czech Republic
  "Reykjavik",   // Iceland
  "Riga",        // Latvia
  "Rome",        // Italy
  "San Marino",  // San Marino
  "Sarajevo",    // Bosnia & Herzegovina
  "Skopje",      // North Macedonia
  "Sofia",       // Bulgaria
  "Stockholm",   // Sweden
  "Tallinn",     // Estonia
  "Tirana",      // Albania
  "Vaduz",       // Liechtenstein
  "Valletta",    // Malta
  "Vatican City",// Vatican
  "Vienna",      // Austria
  "Vilnius",     // Lithuania
  "Warsaw",      // Poland
  "Zagreb"       // Croatia
];

  const textEl = document.getElementById("city-loop");
  const cursorEl = document.querySelector(".cursor");

  let cityIndex = 0;
  let charIndex = 0;
  let currentText = "";
  let isDeleting = false;

  function typeEffect() {
    const fullText = cities[cityIndex % cities.length];

    if (isDeleting) {
      currentText = fullText.substring(0, charIndex--);
    } else {
      currentText = fullText.substring(0, charIndex++);
    }

    textEl.textContent = currentText;

    if (!isDeleting && charIndex === fullText.length) {
      setTimeout(() => (isDeleting = true), 1200);
    } else if (isDeleting && charIndex === 0) {
      isDeleting = false;
      cityIndex++;
    }

    const speed = isDeleting ? 40 : 60;
    setTimeout(typeEffect, speed);
  }

  typeEffect();

  setInterval(() => cursorEl.classList.toggle("hidden"), 500);

  const hero2 = document.querySelector(".hero2");

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        hero2.classList.add("visible");
      }
    });
  });

  observer.observe(hero2);


  window.addEventListener('resize', () => {
  const scale = window.devicePixelRatio || 1;
  document.querySelector('.logo-container').style.filter =
    `blur(${8/scale}px)`;
});