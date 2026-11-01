const passwordInput = document.getElementById("password");

if (passwordInput) {
  const bar = document.getElementById("strength-bar");
  const label = document.getElementById("strength-text");
  const rules = {
    length: value => value.length >= 8,
    lower: value => /[a-z]/.test(value),
    upper: value => /[A-Z]/.test(value),
    number: value => /\d/.test(value),
    special: value => /[^A-Za-z0-9]/.test(value)
  };

  passwordInput.addEventListener("input", () => {
    const value = passwordInput.value;
    let score = 0;
    for (const [name, test] of Object.entries(rules)) {
      const passed = test(value);
      if (passed) score++;
      const element = document.getElementById(`rule-${name}`);
      if (element) element.classList.toggle("passed", passed);
    }

    const percent = (score / 5) * 100;
    bar.style.width = `${percent}%`;
    const messages = ["Not checked", "Very weak", "Weak", "Fair", "Good", "Strong"];
    label.textContent = `Password strength: ${messages[score]}`;
    bar.className = score <= 2 ? "weak" : score <= 4 ? "medium" : "strong";
  });
}
