const text = document.querySelector("#textbox");
const limit = 1000;

document.querySelector("#submit").disabled = true;

text.addEventListener("input", characterCount);

function characterCount() {
    var count = limit - text.value.length;
    var isOver = true;
    var control1 = "characters"
    var control2 = "left";

    if (Math.abs(count) === 1) {
        control1 = "character";
    }

    if (text.value) {
        if (count < 0) {
            count = Math.abs(count);
            control2 = "too many";
        } else {
            isOver = false;
        }
    }
    document.querySelector("#count").innerHTML = `${count} ${control1} ${control2}`;
    document.querySelector("#submit").disabled = isOver;
}
