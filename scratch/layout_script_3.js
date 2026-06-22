
      (function () {
        try {
          const saved = localStorage.getItem("theme");
          const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
          const shouldDark = saved ? (saved === "dark") : prefersDark;
          if (shouldDark) document.documentElement.classList.add("dark");
          else document.documentElement.classList.remove("dark");
        } catch (e) {}
      })();
    