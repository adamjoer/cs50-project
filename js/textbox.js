const text = document.querySelector("textarea");
const limit = 1000;

document.querySelector("#submit").disabled = true;

text.addEventListener("input", characterCount);

function characterCount() {
    var count = limit - text.value.length;
    var isOver = true;
    var control = " characters "
    var msg = limit + control + "left";

    if (Math.abs(count) === 1) {
        control = " character ";
    }

    if (text.value) {
        if (count < 0) {
            msg = Math.abs(count) + control + "too many";
            isOver = true;
        } else {
            msg = count + control + "left";
            isOver = false;
        }
    }
    document.querySelector("#count").innerHTML = (msg);
    document.querySelector("#submit").disabled = isOver;
}
