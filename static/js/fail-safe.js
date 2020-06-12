const checkbox = document.querySelector("#confirm");
const button = document.querySelector("#delete");

button.disabled = true;

checkbox.addEventListener("input", failSafe)

function failSafe() {
    if (checkbox.checked) {
        button.disabled = false;
    } else {
        button.disabled = true;
    }
}
