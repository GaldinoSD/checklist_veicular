
      console.log("[SessionCheck] sessionStorage.session_active =", sessionStorage.getItem('session_active'));
      if (!sessionStorage.getItem('session_active')) {
        console.warn("[SessionCheck] No active session found in sessionStorage. Redirecting to logout...");
        window.location.replace("[]");
      } else {
        console.log("[SessionCheck] Active session verified.");
      }
    