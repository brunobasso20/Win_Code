// Substitua pelas suas chaves do .env (em prod, use process.env ou import)
const SUPABASE_URL = "https://jemrulbggdbzlsncrnbp.supabase.co"; // Do seu .env
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImplbXJ1bGJnZ2RiemxzbmNybmJwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYyMzU0NjQsImV4cCI6MjA3MTgxMTQ2NH0.Mw2XOsJ6lO1HFqqR-jznBoxXvz__Vx-Ceb6WWagjY9E"; // Anon key

const supabase = Supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY); // Inicializa

// Função para alternar seções e atualizar tabs
function showSection(section) {
  document.getElementById("login-form").style.display =
    section === "login" ? "flex" : "none";
  document.getElementById("register-form").style.display =
    section === "register" ? "flex" : "none";

  // Atualiza classes active nos botões
  const buttons = document.querySelectorAll(".tab-button");
  buttons.forEach((button) => {
    button.classList.remove("active");
    if (button.onclick.toString().includes(section)) {
      button.classList.add("active");
    }
  });
}

// Login
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  const message = document.getElementById("login-message");
  if (error) {
    message.textContent = "Erro: " + error.message;
  } else {
    message.textContent = "Login bem-sucedido!"; // Redirecione para dashboard ou index
    console.log(data); // Armazene session no localStorage se precisar
    // Ex: window.location.href = 'index.html';
  }
});

// Registro
document
  .getElementById("register-form")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = document.getElementById("register-email").value;
    const password = document.getElementById("register-password").value;
    const { data, error } = await supabase.auth.signUp({ email, password });
    const message = document.getElementById("register-message");
    if (error) {
      message.textContent = "Erro: " + error.message;
    } else {
      message.textContent = "Registro bem-sucedido! Verifique seu email.";
      console.log(data);
    }
  });

// Inicie mostrando login por default
showSection("login");
