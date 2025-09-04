console.log("🔥 auth.js foi carregado e está rodando");

// Função para alternar seções e atualizar tabs
function showSection(section) {
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");

  if (!loginForm || !registerForm) {
    console.error("❌ Elementos de formulário não encontrados no DOM.");
    return;
  }

  loginForm.style.display = section === "login" ? "flex" : "none";
  registerForm.style.display = section === "register" ? "flex" : "none";

  // Atualiza botões
  const buttons = document.querySelectorAll(".tab-button");
  buttons.forEach((button) => {
    button.classList.toggle("active", button.dataset.section === section);
  });
}

// Espera o DOM carregar para associar eventos
document.addEventListener("DOMContentLoaded", () => {
  // Tabs
  const buttons = document.querySelectorAll(".tab-button");
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      const section = button.dataset.section;
      showSection(section);
    });
  });

  // Login
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("login-email").value;
      const password = document.getElementById("login-password").value;
      const message = document.getElementById("login-message");

      try {
        const res = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok) {
          message.textContent = "Login bem-sucedido! Redirecionando...";
          message.style.color = "green";
          setTimeout(() => (window.location.href = "/sitepersonalizado"), 2000);
        } else {
          message.textContent = "Erro: " + data.error;
          message.style.color = "red";
        }
      } catch (err) {
        message.textContent =
          "Erro de rede. Verifique se o backend está rodando.";
        message.style.color = "red";
      }
    });
  }

  // Registro
  const registerForm = document.getElementById("register-form");
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("register-email").value;
      const password = document.getElementById("register-password").value;
      const message = document.getElementById("register-message");

      try {
        const res = await fetch("/api/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (res.ok) {
          message.textContent = "Registro bem-sucedido! Verifique seu email.";
          message.style.color = "green";
          setTimeout(() => showSection("login"), 2000);
        } else {
          message.textContent = "Erro: " + data.error;
          message.style.color = "red";
        }
      } catch (err) {
        message.textContent =
          "Erro de rede. Verifique se o backend está rodando.";
        message.style.color = "red";
      }
    });
  }

  // Inicia na seção de login
  showSection("login");
});
