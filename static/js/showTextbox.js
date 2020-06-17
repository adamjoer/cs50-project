function showTextbox(element) {
    document.querySelector(".textbox").style.display = "block";
    element.removeAttribute("onclick");
}