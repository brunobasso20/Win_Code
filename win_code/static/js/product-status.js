console.log("product-status.js: Script carregado");

// Função principal para carregar status do produto
async function loadProductStatus() {
  console.log("loadProductStatus: Iniciando execução");

  const circle = document.getElementById("status-circle");
  const text = document.getElementById("status-text");

  if (!circle || !text) {
    console.error("loadProductStatus: Elementos DOM não encontrados", {
      circle,
      text,
    });
    return;
  }
  console.log("loadProductStatus: Elementos DOM encontrados");

  try {
    console.log(
      "loadProductStatus: Fazendo requisição para /api/check_product/sitepersonalizado"
    );
    const response = await fetch("/api/check_product/sitepersonalizado", {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });

    console.log("loadProductStatus: Resposta recebida", {
      status: response.status,
    });

    if (!response.ok) {
      circle.style.backgroundColor = "gray";
      text.textContent =
        response.status === 401 ? "Não autenticado" : "Erro ao carregar";
      removeBuyButton();
      return;
    }

    const data = await response.json();
    console.log("loadProductStatus: Dados recebidos", data);
    const isActive = data.sitepersonalizado_is_active;

    if (isActive === true) {
      console.log("loadProductStatus: Produto ativo");
      circle.style.backgroundColor = "green";
      text.textContent = "Ativo";
      removeBuyButton();
    } else {
      console.log("loadProductStatus: Produto não ativo");
      circle.style.backgroundColor = "red";
      text.textContent = "Não ativado";
      showBuyButton(); // Cria botão somente aqui, após confirmação
    }
  } catch (err) {
    console.error("loadProductStatus: Erro na execução", err);
    circle.style.backgroundColor = "gray";
    text.textContent = "Erro ao carregar";
    removeBuyButton();
  }
}

// Função para criar o botão de compra dinamicamente
async function showBuyButton() {
  if (document.getElementById("buy-product-btn")) return;

  const footer = document.querySelector("footer");
  if (!footer) return;

  const container = document.createElement("div");
  container.id = "buy-product-container";
  container.style.textAlign = "center";
  container.style.margin = "2rem auto";

  const btn = document.createElement("button");
  btn.id = "buy-product-btn";
  btn.className = "cta-button";
  btn.textContent = "Comprar Produto";

  btn.addEventListener("click", async () => {
    try {
      const res = await fetch("/api/create_checkout", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url; // redireciona para checkout Stripe
      } else {
        alert("Erro ao iniciar pagamento");
      }
    } catch (err) {
      console.error("Erro checkout:", err);
    }
  });

  container.appendChild(btn);
  footer.parentNode.insertBefore(container, footer);
}

// Função para remover o botão (se já existir)
function removeBuyButton() {
  const btn = document.getElementById("buy-product-container");
  if (btn) btn.remove();
}

// Executa quando o DOM estiver pronto
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOMContentLoaded: Evento disparado, chamando loadProductStatus");
  loadProductStatus();
});
