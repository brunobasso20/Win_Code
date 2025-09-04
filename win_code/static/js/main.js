document.addEventListener("DOMContentLoaded", function () {
  // --- LÓGICA DA NAVBAR DINÂMICA ---
  const primaryNavbar = document.getElementById("navbar");
  const secondaryNavbar = document.getElementById("navbar-secondary");
  let isSecondaryVisible = false;

  if (primaryNavbar && secondaryNavbar) {
    const navbarHeight = primaryNavbar.offsetHeight;
    console.log("Script carregado, navbarHeight:", navbarHeight); // Depuração

    // Função para verificar se está scrolled para baixo
    const isScrolledDown = () => window.scrollY > navbarHeight;

    // Atualiza visibilidade com base no scroll
    const handleScroll = () => {
      if (!isScrolledDown() && isSecondaryVisible) {
        secondaryNavbar.classList.remove("visible");
        isSecondaryVisible = false;
        console.log("Scroll up, escondendo navbar secundária");
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });

    // Detecção de mouse para mostrar/esconder secundária
    document.addEventListener("mousemove", (e) => {
      if (isScrolledDown()) {
        if (e.clientY < 50 && !isSecondaryVisible) {
          // Mouse na região superior (incluindo barra de URL)
          secondaryNavbar.classList.add("visible");
          isSecondaryVisible = true;
        } else if (e.clientY > 150 && isSecondaryVisible) {
          // Mouse abaixo do threshold
          secondaryNavbar.classList.remove("visible");
          isSecondaryVisible = false;
        }
      }
    });
  } else {
    console.log("Elementos navbar não encontrados:", {
      primaryNavbar,
      secondaryNavbar,
    }); // Depuração
  }

  // --- LÓGICA DO CARROSSEL ---
  const track = document.querySelector(".carousel-track");

  if (track) {
    const slides = Array.from(track.children);
    const nextButton = document.querySelector(".carousel-button--right");
    const prevButton = document.querySelector(".carousel-button--left");
    let currentIndex = 0;

    const updateSlides = () => {
      slides.forEach((slide, index) => {
        if (index === currentIndex) {
          slide.classList.add("current-slide");
        } else {
          slide.classList.remove("current-slide");
        }
      });
    };

    nextButton.addEventListener("click", () => {
      currentIndex = (currentIndex + 1) % slides.length;
      updateSlides();
    });

    prevButton.addEventListener("click", () => {
      currentIndex = (currentIndex - 1 + slides.length) % slides.length;
      updateSlides();
    });

    // Inicia o carrossel
    updateSlides();
  }
});
