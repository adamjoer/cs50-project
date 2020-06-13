function deletenote(el) {
    el.innerHTML = "Delete note?";
    el.setAttribute("href", `/deletenote?note_id=${el.id}`);
    el.removeAttribute("onclick");
}