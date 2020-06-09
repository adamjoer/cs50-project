const text = document.querySelector('textarea');
const limit = 500;

text.addEventListener('input', characterCount);

function characterCount() {

    let count = limit - text.value.length;
    var over = false;

    // console.log("Count: " + count)
    // if (count = 0) {
    //     var control = "character";
    // } else {
    //     var control = "characters";
    // }½

    // WTF IS EVEN GOING ON HERE!?!

    // Assertion failed: Input argument is not an HTMLInputElement

    if (text.value.length > limit) {
        document.querySelector('#count').innerHTML = (-count + " characters too many");
        // console.log((control + " too many"));
        over = true;
    } else {
        document.querySelector('#count').innerHTML = (count + " characters left");
        // console.log((control + " left"));
        over = false;
    }
    document.querySelector('#submit').disabled = over;
}