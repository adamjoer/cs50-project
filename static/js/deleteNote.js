function deletenote(element, id) {
    element.innerHTML = "Are you sure?";
    element.setAttribute("href", `/deletenote?note_id=${id}`);
    element.removeAttribute("onclick");
}