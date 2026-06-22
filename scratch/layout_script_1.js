
      // 🛡️ Injetor Global de Proteção contra CSRF para Formulários e Requisições AJAX (Fetch)
      document.addEventListener("submit", function(event) {
        const form = event.target;
        if (form.method && form.method.toUpperCase() === "POST") {
          // Se o formulário não tiver um input de csrf_token, anexa dinamicamente antes do envio
          if (!form.querySelector('input[name="csrf_token"]')) {
            const tokenMeta = document.querySelector('meta[name="csrf-token"]');
            if (tokenMeta) {
              const input = document.createElement("input");
              input.type = "hidden";
              input.name = "csrf_token";
              input.value = tokenMeta.content;
              form.appendChild(input);
            }
          }
        }
      });

      // Interceptar requisições da Fetch API para anexar automaticamente o cabeçalho X-CSRFToken
      const originalFetch = window.fetch;
      window.fetch = function(input, init) {
        if (init && init.method && ["POST", "PUT", "PATCH", "DELETE"].includes(init.method.toUpperCase())) {
          const tokenMeta = document.querySelector('meta[name="csrf-token"]');
          if (tokenMeta) {
            init.headers = init.headers || {};
            if (init.headers instanceof Headers) {
              if (!init.headers.has("X-CSRFToken")) {
                init.headers.set("X-CSRFToken", tokenMeta.content);
              }
            } else if (Array.isArray(init.headers)) {
              const hasCsrf = init.headers.some(h => h[0].toUpperCase() === "X-CSRFTOKEN");
              if (!hasCsrf) {
                init.headers.push(["X-CSRFToken", tokenMeta.content]);
              }
            } else {
              if (!init.headers["X-CSRFToken"] && !init.headers["x-csrf-token"]) {
                init.headers["X-CSRFToken"] = tokenMeta.content;
              }
            }
          }
        }
        return originalFetch(input, init);
      };
    