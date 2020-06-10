const text = document.querySelector('textarea');
const limit = 1000;

document.querySelector("#submit").disabled = true;

text.addEventListener('input', characterCount);

function characterCount() {

    var count = limit - text.value.length;
    var isOver = true;

    
    // console.log("Count: " + count)
    if (count = 0) {
        var control = "character";
    } else {
        var control = "characters";
    };
            
    // WTF IS EVEN GOING ON HERE!?!

    if (text.value.length) {
        if (count < 0) {
            document.querySelector('#count').innerHTML = (-count + " characters too many");
            console.log((control + " too many"));
            isOver = true;
        } else {
            document.querySelector('#count').innerHTML = (count + " characters left");
            console.log((control + " left"));
            isOver = false;
        }
    }  
    document.querySelector('#submit').disabled = isOver;
}
